# Prebuilt lab apps

Each subfolder here is one intentionally-vulnerable Flask app that the backend
dockerizes and runs in a sandboxed container.

```
labs/default/<lab_slug>/app.py     # the vulnerable app
```

To add one:

1. Create the folder and an `app.py` inside it. It must listen on the port you
   register in step 2 (`app.run(host="0.0.0.0", port=NNNN)`).
2. Add the port to `DEFAULT_PORTS` in `backend/app/services/lab_runner.py`:
   ```python
   DEFAULT_PORTS = {"my_lab": 8094}
   ```
3. Point a vulnerability at it in `backend/app/seed.py`:
   ```python
   "default_lab_slug": "my_lab",
   "lab_objective": "What the learner has to achieve to win.",
   ```
4. Use the token `CYBERLABS_FLAG_PLACEHOLDER` anywhere in the app source. The
   backend replaces it with a fresh random `FLAG{...}` at build time, so the
   flag is never committed to disk.

The app only needs Flask. If your lab needs other packages, add a
`requirements.txt` next to `app.py` and the generated Dockerfile will install it.

This folder is intentionally empty right now.
