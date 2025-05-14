from jinja2 import Environment, FileSystemLoader, Undefined

class SilentUndefined(Undefined):
    def _fail_with_undefined_error(self, *args, **kwargs):
        return ''  # Retorna string vazia em vez de erro
    


env = Environment(loader=FileSystemLoader("./templates"),
                  undefined=SilentUndefined)

template = env.get_template("report.html")
template_empty = env.get_template("empty_report.html")

"""
TODO:
- Create a function to generate the report for each intern
- Load the intern data from the json file
- generate the reports

"""

def generate_html(user_id, html_data):
        
    if html_data["is_empty"]:
        output = template_empty.render(html_data)
    else:
        output = template.render(html_data)
    
    with open(f"../../data/htmls/{user_id}.html", "w") as f:
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