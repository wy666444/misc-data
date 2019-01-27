## xx_game

首先是动态的ELF，其中有几个约束条件会变化，这里先做一些分析拿到一些关键的地址，然后用angr跑对应的函数，基本上两到三秒就可以解出来四个字节的约束结果。此为magic：
```python
def symexec(handler_entry, seccomp_callsite, fail_out):
    project = angr.Project(elf_filename)
    argv1 = claripy.BVS("argv1", 4 * 8)
    state = project.factory.call_state(handler_entry, argv1)
    sm = project.factory.simgr(state)
    sm.explore(find=seccomp_callsite, avoid=[fail_out])
    solution = sm.found[0].se.eval(argv1, cast_to=str)
    return struct.unpack('<i', solution)[0]
```

解出来之后是加载seccomp，直接看ida的结果看不出来猫腻，因为write好像是允许的，但实际上执行的时候是会坏的，于是看了栈，发现有部分ida丢掉的内容，也就是write的参数必须得是write(1, 0x602100, 0x80)，这样就可以把flag打回来了。所以就是需要利用栈溢出实现orw的rop。

这里有一点是程序并没有输出，所以必须得盲打，这里采用的方法是ret2dlresolve的翻版，也就是利用l_addr作为两个函数的差值，加上已解出函数的地址，从而实现任意libc地址的调用，这个操作需要知道是哪个libc版本，之前测试一直是libc6_2.23-0ubuntu9_amd64，另外几个题目也是这个，但是实际上这个题目是libc6_2.23-0ubuntu10_amd64，这个导致最后测试了很久，一直没想到是libc的不同，或者说就算想到了也不知道怎么去测是哪个版本。

函数调用的方面，因为通过pop的gadget最多控制两个寄存器，所以还是要用到csu_init的通用gadget，这个地址要在前面解析的时候一并获取到。

综上的流程：

+ 分析ELF获取到各个关键指令的位置，调用angr完成约束求解，得到magic number
+ 构造link_map，以及读取各种字符串，通过直接到dl_resolve的方式进行库函数调用
+ 首先调用open("./flag", 0)，这里远程的fd是3，本地的是5，后来测试才发现
+ 然后是read(3, 0x602100, 0x80)，这个需要csu_init来准备参数，而实际调用还是rop过去，所以目标函数设成了ret
+ 最后是write(1, 0x602100, 0x80)
