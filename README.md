# README

一个简单的IAT/EAT表hook例子

IAT钩子，就是用Rootkit设计的例程地址替换目标进程IAT表中的地址，从而实现用户层Rootkit想完成的隐匿功能。

为了实现IAT钩子，一般需要：

1. 在内存中定位IAT表
2. 保存表中的操作项
3. 用新地址替换操作项
4. 完成后在恢复该操作项



参考自《The Rootkit Evasion Technology:Attack and Prevention》