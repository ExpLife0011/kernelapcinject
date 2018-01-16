# kernelapcinject
内核执行用户态的shellcode，采用驱动apc形式，支持wow64，测试demo和通讯代码没有了。
此代码wow64单线程执行shellcode，仅供参考，如果你想执行你的wow64demo进程，请从 
kernelAPCinject.c 上的 shellcode32全局常量写入你二进制代码来测试你的demo
如果想支持x64模式的shellcode ，把 APC_MDL_Shellcode_2（）函数的 ((LONG_PTR)pMappedAddress * (-4))改成 (LONG_PTR)pMappedAddress。
即可插入你的x64进程demo。
此驱动支持win7 x64 以上的 64 Bit OS。
