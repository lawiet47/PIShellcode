# PIShellcode - Position-Independent Shellcode Loader

# What is it?

PIShellcode is a Position-Independent shellcode loader. It's basically a C Program compiled as a PIC. It's a modified version of Mr mattifestation's PIC_BindShell project. Here are the details on how to write optimized shellcode for Windwos in C and Visual Studio which he greatly explains. http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html

# To-Do Fix
For whatever reason compiling & linking the code in Visual Studio 2017 with fully optimized arguments `/O1`, The generated code ends up having data segment register offsets to `.rdata` section in it. So in order to actualy obtain position independent code, Maximum optimizatin feature in compiler settings is turned off.

Look-into: merging two sections into one.

#### Maximum Optimized Command Line: `/GS- /TC /GL /W4 /Zc:inline /Fa"x64\Release\" /nologo /Zl /Fo"x64\Release\" /FA /Os /diagnostics:column` -> generates data segment offsets to `.rdata`

![](png/max_optimized_exe.png)

#### Custom Optimized Command Line: `/GS- /TC /GL /W4 /O1 /Zc:inline /Fa"x64\Release\" /nologo /Zl /Fo"x64\Release\" /FA /Os /diagnostics:column` -> generates PIC.


![](png/custom_optimized_exe.png)
