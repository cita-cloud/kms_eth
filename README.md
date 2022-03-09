# kms_eth
`CITA-Cloud`中[kms微服务](https://github.com/cita-cloud/cita_cloud_proto/blob/master/protos/kms.proto)的实现，采用跟以太坊一样的签名算法（`secp256k1`）和哈希算法(`keccak`)组合。
## 编译docker镜像
```
docker build -t citacloud/kms_eth .
```
## 使用方法

```
$ kms -h       
Rivtower Technologies.
This doc string acts as a help message when the user runs '--help' as do all doc strings on fields

USAGE:
    kms <SUBCOMMAND>

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    git     print information from git
    help    Print this message or the help of the given subcommand(s)
    run     run this service
```

### kms-git

打印`git`相关的信息。

```
$ kms git   
git version: 8d5961f-modified
homepage: https://github.com/cita-cloud/kms_eth
```

### kms-run

运行`kms`服务。

```
$ kms run -h
kms-run 
run this service

USAGE:
    kms run [OPTIONS]

OPTIONS:
    -c, --config <CONFIG_PATH>    Chain config path [default: config.toml]
    -h, --help                    Print help information
    -l, --log <LOG_FILE>          log config path [default: kms-log4rs.yaml]
```

参数：
1. 微服务配置文件。

    参见示例`example/config.toml`。

    其中：
    * `kms_port` 为该服务监听的端口号。
    * `db_key` 为加密保存私钥时使用的对称密码。
2. 日志配置文件。

    参见示例`kms-log4rs.yaml`。

    其中：

    * `level` 为日志等级。可选项有：`Error`，`Warn`，`Info`，`Debug`，`Trace`，默认为`Info`。
    * `appenders` 为输出选项，类型为一个数组。可选项有：标准输出(`stdout`)和滚动的日志文件（`journey-service`），默认为同时输出到两个地方。

```
$ kms run -c example/config.toml -l kms-log4rs.yaml
2022-03-09T14:47:37.084545755+08:00 INFO kms - grpc port of this service: 60005
2022-03-09T14:47:37.084630175+08:00 INFO kms - db path of this service: kms.db
2022-03-09T14:47:37.085491258+08:00 INFO kms::kms - get old config: type is eth
2022-03-09T14:47:37.085551188+08:00 INFO kms::kms - verify config
2022-03-09T14:47:37.085601452+08:00 INFO kms::kms - config check ok!
2022-03-09T14:47:37.085641233+08:00 INFO kms - start grpc server!
```

## 设计

密码学算法相关的接口只是对签名算法（`secp256k1`）和哈希算法(`keccak`)的简单封装。

私钥管理部分，类似密码管理软件。

用户配置的`db_key`为主密钥，将其`hash`保存在数据库中，用来在启动的时候进行校验。

创建账户生成的私钥使用主密钥进行对称加密（`AES`），将密文保存在`sqlite`数据库中，并将其在数据库中的序号作为`key_id`返回给用户，用来区分多个账户。

因此，当使用账户私钥，比如签名的时候，需要指定所使用账户的`key_id`。从`sqlite`数据库中加载出私钥的密文之后，再使用主密钥解密，得到原始的私钥。
