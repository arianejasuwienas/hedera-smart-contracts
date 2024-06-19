FROM trailofbits/eth-security-toolbox
RUN mkdir ~/tmp
COPY detectors/hedera/ecrecover_usage_local.py /home/ethsec/tmp/
RUN solc-select install 0.8.24 && solc-select use 0.8.24
RUN mkdir ~/.local/lib/python3.10/site-packages/slither/detectors/hedera
RUN cd ~/.local/lib/python3.10/site-packages/slither/detectors/hedera \
    && rm -rf ../__pycache__ && rm -rf __pycache__  \
    && mv ~/tmp/ecrecover_usage_local.py ecrecover_usage_local.py  \
    && echo 'from .hedera.ecrecover_usage_local import EcrecoverUsage' >> ../all_detectors.py