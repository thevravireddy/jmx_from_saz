The saz_to_jmx_with_req_resp_body_with_filter_param_2files_v1.py is used to convert the saz file (fiddler captured file) to jmeter jmx file.

The python program takes two saz files captured for same scenario, so ideally both of saz files contain same set of api's as they both were collected for same scenario.
The python program uses first argument given saz file as reference to prepare jmx file from it, the sceond argument saz file is used to identify the dynamic parameters
i.e. both saz files are used to check if there are any parameters which can be parameterised by comparing both saz files, if there are parameters to be parameterised, then
respective regex extractor is created as a post processor for a certain http response.

The python progrma takes 4 arguments:
- Path to first SAZ file
- Path to second SAZ file
- Output JMX file path
- Text file containing domains (one per line)

The sample domain file (4th argument) to python program:
blazedemo.com
