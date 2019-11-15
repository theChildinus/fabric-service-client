- 自动生成gRPC代码：Idea 打开 maven工具，Plugins中选择 protobuf，运行 `protobuf:compile` 和 `protobuf:compile-custom`
- 生成带依赖的jar包：`mvn assembly:assembly` ，会在根目录中生成带有 with-dependencies 后缀的jar包

## 证书管理

需要注意：

- 新用户需要先 `register` 再 `enroll` 才可以获得证书和私钥 
- 每次 `enroll` 后会都产生新的证书和私钥，需要重新拷贝给用户使用
- `revoke` 之后不可直接进行 `reenroll`，`reenroll` 一定发生在 `enroll` 之后
- 使用 `getCertificate` 方法返回的是 用户申请过的证书的list 的最后一个，即最新的证书，证书校验也比对的最后一个证书的hash值