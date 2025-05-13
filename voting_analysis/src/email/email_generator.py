from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("./templates"))

template = env.get_template("report.html")

"""
TODO:
- Create a function to generate the report for each intern
- Load the intern data from the json file
- generate the reports

"""

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

output = template.render(data)

with open('output.html', 'w') as f:
    f.write(output)