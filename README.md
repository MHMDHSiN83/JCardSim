# JCardSim (Extended)

This repository is a fork of the official [jCardSim](https://github.com/licel/jcardsim) project, an open-source simulator for Java Card.

This version extends the original simulator with custom applets for Key Management and HKDF (HMAC-based Key Derivation Function), along with comprehensive tests and security improvements.

## 🔗 Original Source
* **Official Repository:** [licel/jcardsim](https://github.com/licel/jcardsim)
* **Project Website:** [jcardsim.org](https://jcardsim.org)

## 🚀 Key Features & Changes

### 1. New Management Applets
Two major applets have been added to the simulator to handle cryptographic operations:
* **KeyManagerApplet:** Handles storage and management of cryptographic keys.
* **HKDFManagerApplet:** Implements the HMAC-based Key Derivation Function (HKDF) logic.

### 2. Security Improvements
* **Dynamic Salt for HKDF:** The HKDF implementation has been upgraded to use a **dynamic salt** rather than a static one, significantly improving the security and randomness of the derived keys.

### 3. Expanded Testing
* **Dedicated Test Suites:** Developed specific tests for both the `KeyManagerApplet` and `HKDFManagerApplet` to ensure stability and correctness of the cryptographic operations.

### 4. Development Environment (QoL)
* **VS Code Support:** Included a `.vscode` directory with build tasks and launch configurations for a seamless Visual Studio Code experience.
* **Maven & Build:** Optimized `pom.xml` for easier dependency management and fat-jar generation.

## 🛠️ Quick Start

### Prerequisites
* Java Development Kit (JDK)
* Maven

### Building the Project
Clone the repository and build using Maven:

```bash
git clone [https://github.com/MHMDHSiN83/JCardSim.git](https://github.com/MHMDHSiN83/JCardSim.git)
cd JCardSim
mvn clean install
