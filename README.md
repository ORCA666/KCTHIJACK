<h1 align="center"> <strong> KCTHIJACK  </strong>  </h1> 

# WHAT IS THIS:
##### KCTHIJACK ; `KernelCallbackTable Hijack`; is a known technique used to run the shellcode after injection, sometimes in other processes, basically using something like `KeUserModeCallback` or pacthing `__fnCOPYDATA` in `KERNELCALLBACKTABLE` struct, However i based this code on something else, this [paper](https://samples.vx-underground.org/APTs/2022/2022.01.27(1)/Paper/blog.malwarebytes.com-North%20Koreas%20Lazarus%20APT%20leverages%20Windows%20Update%20client%20GitHub%20in%20latest%20campaign.pdf) to be more specific, this part here: 

![image](https://user-images.githubusercontent.com/66519611/151924523-761216c1-b244-4ce9-9393-f5781625e8fa.png)
![image](https://user-images.githubusercontent.com/66519611/151929063-335a7a3f-fe49-422e-9673-6ed346b412fe.jpg)

# HOW DOES IT WORK:
* first thing, for anyone that didnt play with `KERNELCALLBACKTABLE` yet, u wont be able to find the pointer to it in peb unless you are loading `user32.dll` or targeting a gui process (with window), thats why a lot of code can be found targeting `explorer.exe`, at least thats what happened to me, so i loaded it [here](https://github.com/ORCA666/KCTHIJACK/blob/c77dc40c4e686d68a775f23c86e95706f25827cb/KCTHijack/main.c#L175)
* Next thing was to get the address of `WMIsAvailableOffline` that is in `wmvcore.dll` So i loaded it and used the typicall `GetProcAddress` to do its job
* the malware used `NtQueryInformationProcess` to get to the peb, and i know it can be done easier than what i did, but i used `PssCaptureSnapshot` && `PssQuerySnapshot` which i will use too in later projects ;p
* after overwriting `WMIsAvailableOffline`'s address with our calc.exe shellcode, the next step was to patch `__fnDWORD` address and let it point to our `WMIsAvailableOffline`, which is our shellcode ...
* of course, managing the memory part ;0, so dont forget about the read/write permissions ...
* now at the end all was left to do was to trigger the shellcode, i used [MessageBoxA](https://github.com/ORCA666/KCTHIJACK/blob/c77dc40c4e686d68a775f23c86e95706f25827cb/KCTHijack/main.c#L157) to do so
* btw i added [this](https://github.com/ORCA666/KCTHIJACK/blob/9ccdfe393e17c0a37a9718264984f5f699f870c4/KCTHijack/main.c#L41) function here, to print out `kct.__fnDWORD`'s value after overwriting so u can see if it is really working

# THANKS FOR:
* [kct](https://github.com/odzhan/injection/blob/master/kct/kct.c) which represent the kernalcallbacktable hijacking method, done on explorer.exe
* And Note That: i dont claim that the method is mine, this method is been around for years, but the analysis paper i read; [North Korea’s Lazarus APT leverages Windows Update client, GitHub in latest campaign](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/) got my attention 

# AT THE END:
#### This is not a code to bypass Av's as is, but a method used to do so, instead of using creatthread or the remote version for example, at the other hand to see how `KeUserModeCallback` method work u can check [this](https://j00ru.vexillium.org/2010/09/kernel-exploitation-r0-to-r3-transitions-via-keusermodecallback/)


![120064592-a5c83480-c075-11eb-89c1-78732ecaf8d3](https://user-images.githubusercontent.com/66519611/123219351-791d0680-d4d5-11eb-8248-e34069d0ad6d.png)
<h6 align="center"> <i> STAY TUNED FOR MORE</i>  </h6> 

