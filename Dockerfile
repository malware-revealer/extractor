# This image is for a production ready extractor

FROM python:3.6-slim

# Install deps
RUN apt-get update && apt-get install -y gcc
# Install mrextractor
RUN pip3 install --no-cache-dir mrextractor

# Execute the extractor by default
ENTRYPOINT ["mrextract"]
