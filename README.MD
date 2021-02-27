# This is a Java library to interface with the [eHSM](https://ellipticsecure.com/products/ehsm_overview.html) and [MIRkey](https://ellipticsecure.com/products/mirkey_overview.html) Hardware Security Modules

Latest release: [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.ellipticsecure/ehsm-java/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.ellipticsecure/ehsm-java)
 [![javadoc](https://javadoc.io/badge2/com.ellipticsecure/ehsm-java/javadoc.svg)](https://javadoc.io/doc/com.ellipticsecure/ehsm-java)

### Maven dependency
```xml
        <dependency>
            <groupId>com.ellipticsecure</groupId>
            <artifactId>ehsm-java</artifactId>
            <version>1.0.6</version>
        </dependency>
```
### Gradle dependency
```groovy
        repositories {
            mavenCentral()
        }
        
        dependencies {
            implementation('com.ellipticsecure:ehsm-java')
        }
```


#### Prerequisites: 
 * Java 8 or later.
 * The ehsm shared library (available [from here](https://ellipticsecure.com/downloads).)

##### Note: You may need to set the EHSM_LIBRARY environment variable if your libehsm.so/dylib/dll is not in a standard location.

#### Build instructions (pre-built libraries are available from Maven Central):
1. ```bash
   mvn package
   ```

See the integration test, LibraryTestIT for some code examples as well as these projects:
   * [java-ehsm-example](https://github.com/ellipticSecure/java-ehsm-example1)
   * [signer-example](https://github.com/ellipticSecure/signer-example)


