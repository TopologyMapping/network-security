# Configuration Guide for Risk Assessment and Feature Datasets

This project uses training and evaluation data extracted from DefectDojo instances running on the VMs: `crivo-dev`, `crivo-class`, and `crivo-num`. These datasets are used to build models for predicting user-assigned risk classifications and analyzing finding features.

---

## Global Path Configuration

The paths below are defined in `settings.py` and indicate where the system expects to find the input and output files. You are free to change these paths according to where you store the extracted pickle files.

```python
RISK_CLASS_GT = pathlib.Path("user_assessments/output_gt_class")
FEATURES_FILE_CLASS_GT = pathlib.Path("finding_features/output_gt_class")

RISK_CLASS_RESIDENTES = pathlib.Path("user_assessments/output_residentes_class")
FEATURES_FILE_CLASS_RESIDENTES = pathlib.Path("finding_features/output_residentes_class")

RISK_NUM_RESIDENTES = pathlib.Path("user_assessments/output_residentes_num")
FEATURES_FILE_NUM_RESIDENTES = pathlib.Path("finding_features/output_residentes_num")

CVE2META_PICKLE_FP = pathlib.Path("data/cve-metadata/cve2meta.pkl.gz")

GRAPHS_OUTDIR = pathlib.Path("report_graphs")
```

To change where these files are loaded from or saved to, simply update their respective paths in the `settings.py` file.

## Extracting Data from DefectDojo VMs

ou can extract training data from the DefectDojo containers using the custom management command `dump_training_sets`, which is available inside the `uwsgi` container.

```python
# Run this inside the uwsgi container to export user assessments (votes/assessments)
docker compose exec -it uwsgi ./manage.py dump_training_sets --data_type="votes" --output_format=""

# Run this to export finding features
docker compose exec -it uwsgi ./manage.py dump_training_sets --data_type="features" --output_format=""
```
You can optionally use the `--filename` argument to set a custom output filename.
> **Note:** For compatibility with older project versions, the `--data_type` used to be `"votes"` for user assessments. In recent versions, it has been renamed to `"assessments"`.

## Exporting Files from the Container

After generating the files, you can copy them from the container to the host using:

```python
# Using docker compose
docker compose cp crivouwsgi-1:<path_inside_container> <path_on_host>

# Or using docker directly
docker cp crivouwsgi-1:/app/crivo-metadata/output_data_features.pickle ./output_data_features.pickle
```

You can repeat this process for each VM: `crivo-dev`, `crivo-class`, `crivo-num`, or new defectdojos with our extension.

## Legacy Naming: vote_class and vote_num

In older versions of the code, the user assessments may have been saved under the names `vote_class` and `vote_num`. These have been renamed to `risk_class` and `risk_num` in the current version. To update these variable names (and to include user email information for each assessment), you can use the script `clean_dataset.py`. This script:

- Renames legacy variable names `vote_*` to the updated `risk_*` names.
- Adds the corresponding user email to each line of assessments using the mapping `JSON_USERS_TO_EMAIL` defined in `settings.py`

> **Note:** This section is only relevant if you're working with data generated using **older versions** of the project.

## File Management Recommendation

You are free to store the extracted `.pickle` files wherever you prefer. Just make sure the global path variables in your `settings.py` point to the correct locations.