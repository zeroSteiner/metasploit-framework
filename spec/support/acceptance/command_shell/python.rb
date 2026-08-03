module Acceptance::Session
  PYTHON = {
    payloads: [
      {
        name: "python/shell_reverse_tcp",
        extension: ".py",
        platforms: [:linux],
        execute_cmd: ["python", "${payload_path}"],
        generate_options: {
          '-f': "raw"
        },
        datastore: {
          global: {},
          module: {}
        }
      },
      {
        name: "cmd/unix/reverse_python",
        extension: ".sh",
        platforms: [:linux],
        execute_cmd: ["sh ${payload_path}"],
        generate_options: {
          '-f': "raw"
        },
        datastore: {
          global: {},
          module: {}
        }
      },
    ],
    module_tests: [
      {
        name: "post/test/unix",
        platforms: [
          :linux,
          :osx,
          [
            :windows,
            {
              skip: true,
              reason: "Unix only test"
            }
          ]
        ],
        skipped: false,
        lines: {
          linux: {
            known_failures: []
          },
          osx: {
            known_failures: []
          },
          windows: {
            known_failures: []
          }
        }
      }
    ]
  }
end
