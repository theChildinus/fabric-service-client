- 自动生成gRPC代码：Idea 打开 maven工具，Plugins中选择 protobuf，运行 `protobuf:compile` 和 `protobuf:compile-custom`
- 生成带依赖的jar包：`mvn assembly:assembly` ，会在根目录中生成带有 with-dependencies 后缀的jar包