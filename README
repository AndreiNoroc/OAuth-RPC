# OAuth RPC Project

## Prerequisites

To run this project, the following dependencies and setup steps are required:

```bash
sudo apt install rpcbind
sudo /etc/init.d/rpcbind start
```

---

## Using the Checker

To compile, test, and clean up the project using the provided checker scripts:

### 1. Compile the project using the Makefile:

```bash
make
```

### 2. Run the checker:

* To run **all tests**:

  ```bash
  ./check.sh all
  ```

* To run a **specific test** (e.g., test number 3):

  ```bash
  ./check.sh 3
  ```

### 3. Clean up generated files:

```bash
make clean
```

---

## Initial Setup

* The base RPC file was generated using:

  ```bash
  rpcgen -C oauth.x
  ```

* The `main` function was copied from `oauth_svc.c` into a new file called `oauth_rpc_server.c`.

* The remaining files were generated separately (as shown in the `Makefile`), including `oauth_svc.h`, which was included as a header in the server file.

---

## File Overview

### `oauth.x`

Defines the RPC structures and procedures required throughout the application.

### `user_data.h`

Includes helper classes for managing and storing user information.

---

## Client Functionality

The client:

* Opens and reads the operations file line by line.
* Determines whether each line represents a **request** or an **operation**.

### For a Request:

* Checks if the user exists.
* Generates an **authorization token**.
* Signs the token and assigns appropriate permissions to the client.
* Generates an **access token** and stores necessary data.
* Displays the resulting information.

### For an Operation:

* Calls the validation procedure.
* Verifies several conditions to determine whether the operation can be executed.

---

## Server Functionality

The server:

* Opens the input files received as command-line arguments.
* Reads data from the files and stores it in appropriate data structures.
* Implements the required procedures to interact with the client.
* Processes and manipulates the data read from the files within these procedures.

---

## Additional Notes

* Modified the test reference files to include a newline at the end.
* Cleaned up the README content to remove outdated sections, keeping only valid and relevant info.
* Added necessary parameters to the checker script to support testing.

---

## License

This project is developed for educational purposes and is provided as-is.
