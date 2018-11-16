# Wireshark可用的BOLT协议解析插件

`Wireshark`是排查网络问题最常用的工具，它已经内置支持了上百种通用协议，扩展性也好,对于私有协议,还是得自己写的.对 C 不熟,但是 Lua 看了一下语法,还是挺简单的.

插件是使用lua开发的，安装比较简单，以OS X平台为例：

1. 将协议解析脚本拷贝到`/Applications/Wireshark.app/Contents/Resources/share/wireshark/` 目录
2. (非必须) 编辑`init.lua`文件，设置`disable_lua = false`，确保lua支持打开,默认是打开的.一般就不要操作了.
3. 在`init.lua`文件末尾增加
```
dofile("bolt.lua")
```
当然你也可以写全路径.

4.再次启动`Wireshark`，会对12200端口的数据流使用脚本解析，已经可以识别`BOLT`协议了。


# 请求

![reqeust](https://github.com/leizhiyuan/bolt-dissector/raw/master/src/media/request.png)

# 响应

![response](https://github.com/leizhiyuan/bolt-dissector/raw/master/src/media/response.png)

# 心跳

![heart](https://github.com/leizhiyuan/bolt-dissector/raw/master/src/media/heart.png)


# 参考文档

https://wiki.wireshark.org/LuaAPI