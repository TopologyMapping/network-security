from jinja2 import Environment, FileSystemLoader, Undefined
import os


def categorical_format(value):
    MILD_UPPER_THRESHOLD = 1.75
    MODERATE_UPPER_THRESHOLD = 2.5
    SEVERE_UPPER_THRESHOLD = 3.25
    
    if value < MILD_UPPER_THRESHOLD:
        return f"Mild({value})"
    elif value < MODERATE_UPPER_THRESHOLD:
        return f"Moderate({value})"
    elif value < SEVERE_UPPER_THRESHOLD:
        return f"Severe({value})"
    else:
        return f"Critical({value})"


class SilentUndefined(Undefined):
    def _fail_with_undefined_error(self, *args, **kwargs):
        return ''  # Retorna string vazia em vez de erro
    


env = Environment(loader=FileSystemLoader("./templates"),
                  undefined=SilentUndefined)

env.filters["categorical_format"] = categorical_format

template = env.get_template("report.html")
template_empty = env.get_template("empty_report.html")

"""
TODO:
- Create a function to generate the report for each intern
- Load the intern data from the json file
- generate the reports

"""

def generate_html(html_data, filename="default", categorical=False):
        
    if html_data["is_empty"]:
        output = template_empty.render(html_data)
        empty_dir = "../../data/htmls/empty/"
        if not os.path.exists(empty_dir):
            os.makedirs(empty_dir)
        with open(f"{empty_dir}{filename}.html", "w") as f:
            f.write(output)
    else:
        output = template.render(html_data)
        
        if categorical:
            categorical_dir = "../../data/htmls/categorical/"
            if not os.path.exists(categorical_dir):
                os.makedirs(categorical_dir)
            with open(f"{categorical_dir}{filename}.html", "w") as f:
                f.write(output)
                
        else:
            numerical_dir = "../../data/htmls/numerical/"
            if not os.path.exists(numerical_dir):
                os.makedirs(numerical_dir)
            with open(f"{numerical_dir}{filename}.html", "w") as f:
                f.write(output)

if __name__ == "__main__":

    data = {
        "intern_name": "John Doe",
        "file_name": ["image1.png", "image2.png"],
        "highlight_vuln": [
            {
                "title": "finding1",
                "id": "3",
                "intern_rank": "high",
                "mean_rank": "medium",
                "variance": "low"
            },
            {
                "title": "finding2",
                "id": "3",
                "intern_rank": "high",
                "mean_rank": "medium",
                "variance": "low"
            },
            {
                "title": "finding3",
                "id": "3",
                "intern_rank": "high",
                "mean_rank": "medium",
                "variance": "low"
            }
        ]
    }



    generate_html("1", data)