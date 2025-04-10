# 4985-servera Repository Guide
## **Table of Contents**

1. [Cloning the Repository](#cloning-the-repository)
2. [Running the `generate-cmakelists.sh` Script](#running-the-generate-cmakelistssh-script)
3. [Running the `change-compiler.sh` Script](#running-the-change-compilersh-script)
4. [Running the `build.sh` Script](#running-the-buildsh-script)
5. [Running the `build-all.sh` Script](#running-the-build-allsh-script)
6. [Copy the template to start a new project](#copy-the-template-to-start-a-new-project)
7. [Running the application](#running-the-application)

## **Cloning the Repository**

Clone the repository using the following command:

```bash
git clone https://github.com/R-Lok/4985-proj-servera.git
```

Navigate to the cloned directory:

```bash
cd 4985-proj-servera

```

Ensure the scripts are executable:

```bash
chmod +x *.sh
```

Link your .flags folder

```bash
./link-flags.sh <path to your .flags folder>
```

Copy your santizers.txt and supported_c_compilers.txt files into the directory

```bash
cp <path to your sanitizers.txt> .
cp <path to your supported_c_compilers.txt> .
```

## **Running the generate-cmakelists.sh Script**

You will need to create the CMakeLists.txt file:

```bash
./generate-cmakelists.sh
```

## **Running the change-compiler.sh Script**

Tell CMake which compiler you want to use:

```bash
./change-compiler.sh -c <compiler>
```

To the see the list of possible compilers:

```bash
cat supported_cxx_compilers.txt
```

## **Running the build.sh Script**

To build the program run:

```bash
./build.sh
```

## **Running the build-all.sh Script**

To build the program with all compilers run:

```bash
./build-all.sh
```

## **Running the application**

To run the application after building

```bash
./build/starter -i <IPv4 address of server manager> -p <port of server manager>
```
The -p flag and argument is optional. If not provided, it will connect to port 9000.
