from avatar2 import *
from pwn import u8, u32
import subprocess
import cle, os, sys
from srcAVD import config 
from srcAVD.memory import Memory, GlobalMemory
from srcAVD.summaries import *
from srcAVD.bilExec import BilExec
from srcAVD.program import Program
from srcAVD.utils import isSymbolic
from srcAVD.adt import *

def getArgs():
    args = []
    for arg in config.ARGV:
        if type(arg) == int:
            args.append('A'*arg)
        else:
            args.append(arg)
    return ' '.join(args)

def fixArgs(mem):
    argCount = 0
    if config.ARCH == config.x86:
        esp = mem.load('ESP')
        argv = mem.load(esp.val + 8).val

        for arg in config.ARGV:
            argCount += 1
            argv += 4 #We dont care about the first one (name of the binary)
            argAddr = mem.load(argv)
            if type(arg) == int:
                for b in range(arg):
                    val = BitVec('arg_{}_{}'.format(argCount, b), 8)
                    mem.storeByte(argAddr.val+b, ADT(val)) #Insert symbolic stuff here
    else:
        #64 bits. Main arguments are in registers rsi (argv) and rdi(argc)
        argv = mem.getFromMem('RSI').val
        for arg in config.ARGV:
            argCount += 1
            argv += 8 #We dont care about the first one (name of the binary)
            argAddr = mem.load(argv)
            if type(arg) == int:
                for b in range(arg):
                    val = BitVec('arg_{}_{}'.format(argCount, b), 8)
                    mem.storeByte(argAddr.val+b, ADT(val)) #Insert symbolic stuff here

class AvatarGDBConcreteTarget():
   
    def __init__(self, gdbserver_ip, gdbserver_port, binary):
        # Creation of the avatar-object
        if config.ARCH == config.x86:
            self.avatar = Avatar(arch=archs.x86.X86)
        else:
            self.avatar = Avatar(arch=archs.x86.X86_64)

        self.target = self.avatar.add_target(GDBTarget, gdb_executable="gdb", gdb_ip=gdbserver_ip, gdb_port=gdbserver_port)   
        
        cb_env = {'seed': '414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141'}
        args = getArgs()

        self.gdbserver = subprocess.Popen('gdbserver --once {}:{} {} {}'.format(gdbserver_ip, gdbserver_port, binary, args), shell=True, env=cb_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        self.target.init()
        self.memmap = self.get_mappings()

        config.BASE_ADDR = self.memmap[0].start_address

        entry = self.target.protocols.memory.get_symbol('main')
        if not entry[0]:
            config.STRIPPED_BINARY = True
            if config.ARCH == config.x86:
                print('Can not handle 32-bit stripped binaries yet.')
                exit()
            else:
                #Find main another way
                if config.IS_PIE:
                    entry = config.BASE_ADDR + find_main()
                else:
                    entry = find_main()
                    
                print('Binary is stripped. base = {}, main = {}'.format(hex(config.BASE_ADDR), hex(entry)))
        else:
            entry = entry[1]

        self.target.set_breakpoint(entry)
        self.target.cont()

        self.target.wait(TargetStates.STOPPED | TargetStates.EXITED)

        if self.target.state == TargetStates.EXITED:
            print('Something went wrong while trying to go to main. Main addr={}'.format(hex(entry)))
            terminate()
            exit()
        else:
            print('All good')

        self.target.remove_breakpoint(entry)


        #Synchronize cle loader with gdbserver. FIXME: Isn't there an option to do that already?  
        main_opts = {'base_addr': self.memmap[0].start_address}
        lib_opts = {}
        for i in self.memmap:  
            if i.name != 'unknown' and not i.name.startswith('['):
                if i.name not in lib_opts:
                    lib_opts[i.name] = {'base_addr': i.start_address}   

        self.ld = cle.Loader(binary, lib_opts = lib_opts, main_opts=main_opts) #, auto_load_libs=False)

        #Let stack occupy as much as it wants
        for i in range(0, len(self.memmap)):
            if self.memmap[i].name == '[stack]':
                self.memmap[i].start_address = self.memmap[i-1].end_address

        #Setup everything to execute concretely
        self.mem = Memory(self)
        self.gm = GlobalMemory()
        self.initGlobals()
        self.mem.gm = self.gm
        self.mem.initMem()

        self.program  = Program(binary, self)
        self.executor = BilExec(self.mem, self.program)

        self.canBeUndefined = True

        #Careful with tainted values! And RBP/ReturnAddress overflow checks!
        #if config.SYM_EXEC:
        #    self.executeConcretelyUntilNeeded()

        self.mem.initMem() #Update register values

        fixArgs(self.mem) #Update symbolic arguments if any

        if config.O1_ENABLED:
            self.dumpMemoryContents()

        self.canBeUndefined = False

    def initGlobals(self):

        for section in self.memmap:
            if section.name == '[heap]':
                heap_start = section.start_address
                heap_end = section.end_address
                break
        else:
            return #No heap...

        allocats = []
        for obj in self.ld.all_objects:
            for sym in obj.symbols:
                if sym.rebased_addr >= heap_start and sym.rebased_addr < heap_end:
                    for i in range(config.ARCH.size//8):
                        allocats.append(sym.rebased_addr + i)

        allocats.sort()
        current = None

        for a in allocats:
            if current == None:
                current = (a, a)
            elif a == current[1]+1:
                current = (current[0], a)
            else:
                rang = MemRange(current[0], current[1]+1) #End is exclusive
                self.gm.allocatedRanges.append(rang)
                current = None


    def dumpMemoryContents(self):
        mem = self.mem

        for m in self.memmap:
            size = m.end_address - m.start_address
  
            print('Copying {} bytes from section {}'.format(size, m.name))
                      
            try:
                contents = self.read_memory(m.start_address, size, raw=True)
            except:
                print('Error copying data. Its probably not important anyway')
                continue

            addr = m.start_address
            for b in contents: #For each byte...
                mem.m[addr] = ADT(b)
                addr += 1

    def executeConcretelyUntilNeeded(self):
        self.mem.concreteMemory = True
        print('Executing concretely...')

        #Summaries that may introduce symbolic variables
        #if config.SYM_EXEC:
        self.symIntroducingSummaries = ('_IO_fgets', '_IO_gets', 'getchar', 'fgets','gets','read','__isoc99_scanf')
        #else:
            #If we want APG to execute concretely and still be useful,
            #    we might aswell start from the beginning (main)
            #self.symIntroducingSummaries = ('main')

        self.mallocLikeSummaries = ('malloc','calloc')

        for i in list(self.symIntroducingSummaries) + list(self.mallocLikeSummaries):
            address = self.target.protocols.memory.get_symbol(i)
            address2 = self.target.protocols.memory.get_symbol(i + '@plt') #PLT address
            if address[0]:
                address = address[1]
                print('Inserting breakpoint at {} ({})'.format(hex(address), i))
                self.target.set_breakpoint(address)
            if address2[0]:
                address2 = address2[1]
                print('Inserting breakpoint at {} ({})'.format(hex(address2), i))
                self.target.set_breakpoint(address2)

        while 1:
            self.target.cont()
            self.target.wait(TargetStates.STOPPED | TargetStates.EXITED)

            if self.target.state == TargetStates.EXITED:
                print('No symbolic input is requested')
                terminate()
                exit()

            address = self.target.read_register(config.ARCH.ipReg.lower())
            
            func = self.ld.describe_addr(address)
            print('[{}] Currently in'.format(self.target.state), hex(address), '-->', func)
            func = func.split('+')[0]

            if func.startswith('PLT.'):
                func = func[4:]

            if func in self.mallocLikeSummaries or func in self.symIntroducingSummaries:
                assert func in summaries
                code = summaries[func]
                if func in self.symIntroducingSummaries:
                    break

                code.execute(self.executor, self.mem)


        self.mem.concreteMemory = False
        print('Finished executing concretely...')

    def exit(self):
        self.avatar.shutdown()
        self.gdbserver.terminate()

    def read_instructions(self, addr, size):
        if config.O1_ENABLED:
            return bytes([self.gm.getFromBaseMem(addr + i) for i in range(size)])
        else:
            return self.read_memory(addr, size)

    def read_memory(self, address, nbytes, **kwargs):
        """
        Reading from memory of the target

            :param int address: The address to read from
            :param int nbytes:  The amount number of bytes to read
            :return:        The memory read
            :rtype: str
            :raise angr.errors.SimMemoryError
        """

        assert not isSymbolic(address)

        try:
            return self.target.read_memory(address, 1, int(nbytes), raw=True)
        except Exception as e: #Segfault...
            if e.args[0] == 'read_memory() requested but memory is undefined.':
                print('GDB Target is down...')
                terminate()
                exit()

            elif e.args[0] == 'Failed to read memory!':
                if self.canBeUndefined:
                    return b'\x00'
           
                else:
                    print('Segmentation fault ({})'.format(hex(address)))
                    return None

            else:
                print('Unknown exception occured:', e)
                print(e.args)
                terminate()

        
    def loadByte(self, value):
        val = self.read_memory(value, 1)
        if val is not None:
            return u8(val)

    def load(self, addr, size=None, noneIsFine=False):
        if size is None:
            size = config.ARCH.size

        if size == 1: #We only read bits from flags or vars actually
            assert type(addr) == str

        if type(addr) == str:
            val = self.read_register(addr)
            if val is not None:
                return twoComplement(val, size)
            if noneIsFine:
                return None

            self.printMemory()
            print('This shouldnt have happened... Tried to access', addr)
            terminate()

        assert size >= 8 and size % 8 == 0, "size should be multiple of 8... instead is {}".format(size)
        s = size // 8
        

        l = [self.loadByte(addr+i) for i in range(s)]
        l = l[::-1] #Little endian
    
        res = 0
        for i in l:
            if i is None:
                return None
            res = res * 256 + i

        return res

    def storeByte(self, dest, val):
        assert  val & 0xFF == val
        self.target.write_memory(dest, 1, val)

    def store(self, dest, val, size=None):
        if size is None:
            size = config.ARCH.size

        if size == 1:
            assert type(dest) == str 

        if type(dest) == str:
            self.write_register(dest, twoComplement(val, size))

        else:
            while size > 0:
                self.storeByte(dest, val & 0xFF)
                val = val >> 8
                size -= 8
                dest += 1


    def read_register(self,register,**kwargs):
        """"
        Reads a register from the target
            :param str register: The name of the register
            :return: int value of the register content
            :rtype int
            :raise angr.errors.ConcreteRegisterError in case the register doesn't exist or any other exception
        """
        register_value = self.target.read_register(register.lower())
        # when accessing xmm registers and ymm register gdb return a list of 4/8 32 bit values
        # which need to be shifted appropriately to create a 128/256 bit value
        if type(register_value) is list:
            i = 0
            result = 0
            for val in register_value:
                cur_val = val << i * 32
                result |= cur_val
                i += 1
            return result
        else:
            return register_value

    def write_register(self, register, value):
        self.target.write_register(register, value)

    def read_tls(self, cur_ip, addr, size):
        #tls = self.ld.find_object_containing(cur_ip)
        tls = self.ld.find_object('libc.so') #FIXME this doesnt make sense... but works... why?
        res = tls.memory.load(tls.tls_data_start+addr, size//8)
        return res
        #print('TLSACCESS - {} = {}'.format(addr, res))

    def get_mappings(self):
        """Returns the mmap of the concrete process
        :return:
        """

        class MemoryMap:
            """
            Describing a memory range inside the concrete
            process.
            """
            def __init__(self, start_address, end_address, offset, name):
                self.start_address = start_address
                self.end_address = end_address
                self.offset = offset
                self.name = name

            def __str__(self):
                my_str = "MemoryMap[start_address: 0x%x | end_address: 0x%x | name: %s" \
                      % (self.start_address,
                         self.end_address,
                         self.name)

                return my_str

            def containsAddr(self, addr):
                return addr >= self.start_address and addr < self.end_address

        mapping_output = self.target.protocols.memory.get_mappings()

        mapping_output = mapping_output[1].split("\n")[4:]

        vmmap = []

        for mapp in mapping_output:
            mapp = mapp[2:].lstrip(' ')
            mapp = mapp.split(" ")

            # removing empty entries
            mapp = list(filter(lambda x: x not in ["\\t", "\\n", ''], mapp))

            map_start_address = mapp[0].replace("\\n", '')
            map_start_address = map_start_address.replace("\\t", '')
            map_start_address = int(map_start_address, 16)
            map_end_address = mapp[1].replace("\\n", '')
            map_end_address = map_end_address.replace("\\t", '')
            map_end_address = int(map_end_address, 16)
            offset = mapp[3].replace("\\n", '')
            offset = offset.replace("\\t", '')
            offset = int(offset, 16)
            if len(mapp) == 5:
                map_name = mapp[4].replace("\\n", '')
                map_name = map_name.replace("\\t", '')
                map_name = os.path.basename(map_name)
            else:
                map_name = 'unknown'
            vmmap.append(MemoryMap(map_start_address, map_end_address, offset, map_name))

        return vmmap



if __name__ == '__main__':
    GDB_IP = '127.0.0.1'
    GDB_PORT = 9999

    binary = 'exampleProgs/arch32'

    concrete = AvatarGDBConcreteTarget(GDB_IP, GDB_PORT, binary)

    #Try to read rtld_global table... answer should be 0xf7ffd940
    print(hex(u32(concrete.read_memory(0xf7ffd040, 4))))
    input('PRESS ENTER')

    concrete.exit()
