# Password Detection Program

In order to utilize this password detection program, you must do the following:

1) Open your Terminal window.
2) In your Terminal window, type in "cd e-passtool" and enter. Do this a second time to access the tool itself.

To store a password, run "python3 (cipher.py) store (1|2|3) (password)"

To retrieve a password, run "python3 ceasar_cipher.py password (1|2|3)"

To encrypt a password, run "python3 ceasar_cipher.py encrypt (1|2|3)"

To unencrypt a password, run "python3 ceasar_cipher.py unencrypt (1|2|3)"

This program utilizes numerous ciphers to encrypt passwords (Affine, Ceasar, transposition, Vigenere)
It can hold up to three unique passwords.
It supports negative integers as well, which means you can easily undo a Caesar cipher by using its negative shift value as an input.
