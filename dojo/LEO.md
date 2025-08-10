# Problem Mappings for Findings Disambiguation

This project utilizes mappings from a JSON file to disambiguate findings across various security tools, such as Nmap, OpenVAS, Metasploit, and Nuclei. The mappings help to group equivalent or similar findings under the same problem ID, simplifying the analysis and response to security vulnerabilities.

## Problem Mappings JSON Structure

The JSON file should follow this structure:

```json
{
    "problem_id_1": ["script_id_1", "script_id_2", "script_id_3"],
    "problem_id_2": ["script_id_4", "script_id_5"],
    "problem_id_3": ["script_id_6"]
}
```
## Enabling the Mapping

To enable the problem mappings, you can use the following configuration:

### Using a Remote URL
```python
PROBLEM_MAPPINGS_JSON_URL = "https://pugna.snes.dcc.ufmg.br/defectdojo/disambiguator.json"
```

### Using a Local File Path
If the JSON file is available locally, you can reference it using a `file://` URL:
```python
PROBLEM_MAPPINGS_JSON_URL = "file:///app/dojo/fixtures/disambiguator.json"
```

Once you set this URL in the configuration, the `Problems` tab in the Dojo UI will be activated, and it will use the JSON from the provided link to disambiguate findings during the parsing of Nmap, OpenVAS XML, and Nuclei tools.

If the mapping fails or there are no mappings for a particular finding, the Problems tab will group findings based on their `script_id`, using the script ID of the tool that detected them.

