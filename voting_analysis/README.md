# Vulnerability Assessment Analysis

Analysis of intern vulnerability assessments, generating reports, and identifying assessment styles.

## Project Setup

### Prerequisites

- Python 3.8 or higher
- PDM (Python Dependency Manager)

### Installing PDM

This project uses PDM for dependency management. If you don't have PDM installed, please follow the installation instructions on the [official PDM documentation](https://pdm.fming.dev/latest/#installation).

### Setting Up the Project

1. Clone this repository:
   ```bash
   git clone https://github.com/BernnardoSBO/crivo_feedback_analysis.git
   cd crivo_feedback_analysis
   ```

2. Initialize the project with PDM:
   ```bash
   pdm install
   ```
   This will:
   - Create a virtual environment
   - Install all project dependencies
   - Install the project itself in editable mode

3. Activate the PDM-managed environment:
   ```bash
   # Option 1: Use PDM to run commands
   pdm run python -m vulnerability_analysis.your_script

   # Option 2: Activate the environment (shell-specific)
   eval $(pdm venv activate)  # For Bash/Zsh
   ```

### Project Configuration

Project configuration is managed through `pyproject.toml`. You can modify analysis parameters, file paths, and other settings in the `[tool.vulnerability_analysis]` section of this file.

## Project Structure

```
├── data
│   ├── ...
├── src
│   ├── data_prep.ipynb
│   └── __init__.py
└── tests
|   ├── __init__.py
|   └── __pycache__
├── pdm.lock
├── __pycache__
├── pyproject.toml
├── README.md
```

## Usage

### Generating Individual Reports

<!-- ```bash
pdm run python -m vulnerability_analysis.generate_reports
```

### Running Analysis

```bash
pdm run python -m vulnerability_analysis.run_analysis
```

### Using the Jupyter Notebooks

```bash
pdm run jupyter notebook
``` -->

## Development

### Adding Dependencies

```bash
# Add a runtime dependency
pdm add pandas

# Add a development dependency
pdm add --dev pytest
```

### Running Tests

```bash
pdm run pytest
```

## License

MIT
