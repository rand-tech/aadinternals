# aadinternals

aadinternals is a Pythonic implementation of the "AADInternals" tool.

This is a very WIP project, and is not yet feature complete.  If you want to implement a feature, please feel free to submit a PR.

- Installation
    ```sh
    pip install git+https://github.com/rand-tech/aadinternals.git
    ```
- Cheat Sheet
  - Domain
    ```sh
    python -m aadinternals recon domain.example.com
    ```
  - Email
    ```sh
    python -m aadinternals recon sombody@domain.example.com
    ```
  - Save images
    ```sh
    python -m aadinternals recon domain.example.com -i /path/to/save/images
    shasum /path/to/save/images/*|awk '!seen[$1]++ {print $2}' # check images
    ```
  - Use JSON output
    ```json
    $ python -m aadinternals recon domain.example.com -t json 2>/dev/null
    {
      "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "yyyyyyyyyyyyyyyyyyyyyyyy",
      "brand": "hmm.example.com",
      "region": "AS",
      "sso": false,
      "uses_cloud_sync": false,
      "domains_info": [
        {
          "name": "hmm.example.com",
          "dns": true,
          "mx": false,
          "spf": false,
          "type": "Managed",
          "dmarc": false,
          "dkim": false,
          "mta_sts": false,
          "sts": "",
          "rps": null,
          "brand": "hmm.example.com",
          "branding_urls": null
        },
        {...
        }
      ]
    }
    ```

## Acknowledgments

This project builds upon the work done in the following projects:

- [AADInternals](https://github.com/Gerenios/AADInternals) by Gerenios
- [AADOutsider-py](https://github.com/synacktiv/AADOutsider-py) by Synacktiv

While improvements and changes have been made, we acknowledge and appreciate the foundation provided by these projects.

## Disclaimer

This tool is for educational and ethical testing purposes only. Always ensure you have explicit permission before performing any reconnaissance or testing on systems you do not own or have explicit permission to test.

Be cool.

Don't get me in trouble! :)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

If you encounter any problems or have any questions, please open an issue on the GitHub repository.
