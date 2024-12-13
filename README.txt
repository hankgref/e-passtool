In order to utilize this password detection program, you must do the following:
1) Open your Terminal window.
2) In your Terminal window, type in "cd e-passtool" and enter. Do this a second time to access the tool itself.




To store a password, run: "python3 password_storage.py store (insert password here)"

To print the stored password, run: "python3 password_storage.py password"

To encrypt the stored password, run: "python3 password_storage.py encrypt (shift value)"

For help, run: "python3 password_storage.py help"


This program utilizes a Caesar cipher in order to encrypt the password.
It supports negative integers as well, which means you can easily undo a Caesar cipher by using its negative shift value as an input.