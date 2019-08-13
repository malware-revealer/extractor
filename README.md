# Malware Revealer Extractor

A library for binaries feature extraction, it enables doing static analysis on binaries for extracting the exact information you need.


## Example

TODO: GIF showing an example of extracting a feature from an example binary


## Installation

Install mrextractor using pip

```bash
pip install mrextractor
```

You can also install it from source

```bash
$ git clone https://github.com/malware-revealer/extractor/
$ cd extractor
$ python3 setup.py install
```

Both will install mrextractor as well as its dependencies listed under [requirements.txt](https://github.com/malware-revealer/extractor/blob/master/requirements.txt)


## Extract Features from Binaries

If you want to extract some features from only one or few binaries without using the batch feature then check this [quick tutorial](#).

For extracting features from a dataset of binaries then you will first need to prepare your dataset into a simple folder hierarchy as shown below (each subdirectory represents a class of executables, here we have two classes '0' and '1', but you may use classes like 'malware' or 'trojan' as well)

```bash
$ tree executables/
executables/
├── 0
│   └── example.exe
└── 1
    └── example.exe
```

Then you will need to list the features you wanna extract in a configuration file, check this [wiki page](#) to learn setup the extractor. If one of the features isn't already implemented, you can either make an issue an wait for someone to implement it, or implement it yourself and make a Pull Request :) check this [wiki page](#) to learn how to do that.

You are now all set to start the extraction. If you have mrextractor already installed then you can use it directly to start the extraction, if you haven't then you can use our Docker image to do so without installing mrextractor. Check steps below.

#### Extract using the mrextractor

Installing mrextractor will also add the mrextract utility that you can use for making batch extraction on a dataset of binaries.

I will now assume that you have the dataset and the configuration file in the working directory as ./executables/ and ./conf.yaml, if you haven't do so already then please check steps above.

```bash
$ mrextract
usage: mrextract [-h] [-o OUTPUT_DIR] [-l LOG_FILE] conf_file input_dir
$ mrextract ./conf.yaml ./executables -o ./out
```

You will then find the extracted features under ./out


#### Extract using the docker image

You can use this Docker [image](https://hub.docker.com/r/malwarerevealer/extractor) to make extraction without the need to install mrextractor.

I will now assume that you have the dataset and the configuration file in the working directory as ./executables/ and ./conf.yaml, if you haven't do so already then please check steps above.

```bash
$ docker container run --rm -v $PWD:/data:ro -v $PWD/out:/out malwarerevealer/extractor /data/conf.yaml /data/executables -o /out
```

You will then find the extracted features under ./out


## Tutos

TODO


## License

[MIT License](https://github.com/malware-revealer/extractor/blob/master/LICENSE)
