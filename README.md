# Excel Plus

基于 BouncyCastle 库，AES 和 RSA 加解密库

## 怎么使用

### Gradle
1. 配置 maven 库
   ```
   repositories {

     maven {
       url = uri("https://central.sonatype.com/repository/maven-snapshots/")
     }
   
    //...

   }
   ```
2. 配置依赖
   ```
   dependencies {
    implementation('com.ericyl.utils:cryptographical:0.1.0-SNAPSHOT')
   }
   ```

## 使用到的类库
1. [BouncyCastle](https://www.bouncycastle.org)