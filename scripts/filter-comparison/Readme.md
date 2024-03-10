# filter-comparison

This provides a way to easily evaluate the performance difference between using rayon vs multiple dedicated threads to execute the hot-code path where events are checked against all directive rules.

At the time of writing, dedicated threads are more performant than rayon for dsiem specific use case, and so it is the one used in directive manager and rule.

## Usage

Activate rayon by setting the environment variable `USE_RAYON` to `true`, or set it to `false` or unset to use dedicated threads.

Other environment variables that can be set are:
- `RAYON_THREAD_POOL_SIZE` to set the number of threads used by rayon
- `DIRECTIVES_PER_THREAD` to set the number of directives processed by each dedicated thread

After setting the environment variables:

- Put a directive.json file with at least a thousand entries in /configs directory, i.e.:
  
  ```shell
  mkdir -p ./target/debug/configs && ln -s /absolute/path/to/directive.json ./target/debug/configs/directive.json
  ```

- Execute one of the following command to start the server (release version is more performant):

  ```shell
  cargo run -p filter-comparison
  cargo build --release -p filter-comparison && ./target/release/filter-comparison
  ```

- Send a POST request using [dtester](https://github.com/defenxor/dsiem/tree/master/cmd/dtester):

  ```shell
  ./dtester dsiem -d 192.168.0.1 -f <path-to-directive.json-above> -p 6667 -r [eps]
  ```

- Try different values for `eps` and compare the performance between rayon and dedicated threads.
