# identity-idp-attempts-tracker-events

An example of a idp attempts tracker events written as a simple Sinatra app in Ruby.

## Running locally

These instructions assume [`identity-idp`](https://github.com/18F/identity-idp) is also running locally
at http://localhost:3000 .

1. Set up the environment with:

  ```
  $ make setup
  ```

2. And run the app server:

  ```
  $ make run
  ```

3. To run specs:

  ```
  $ make test
  ```

This sample app is configured to run on http://localhost:9292 by default. Optionally, you can assign a custom hostname
or port by passing `HOST=` or `PORT=` environment variables when starting the application server.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.test
