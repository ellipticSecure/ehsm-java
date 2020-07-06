# This is the Java library to interface with the [eHSM](https://ellipticsecure.com/products/) and [MIRkey](https://ellipticsecure.com/products/) Hardware Security Modules

### Maven dependency:
```xml
        <dependency>
            <groupId>com.ellipticsecure</groupId>
            <artifactId>ehsm-java</artifactId>
            <version>1.0.3</version>
        </dependency>
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


