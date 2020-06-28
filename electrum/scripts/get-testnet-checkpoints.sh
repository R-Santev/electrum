#!/bin/bash


echo "begin to find checkpoints hash..."

checkpoints="["

for((i=2015; i<78152; i+=2016))
do
	hash=`bgold-cli -testnet -rpcuser=tolak -rpcpassword=123 -rpcport=18332 getblockhash $i`
	echo "get block hash: $i - $hash"
	checkpoints=${checkpoints}"\n[\n	\"$hash\",\n	0\n],"
done
checkpoints=${checkpoints}"\n]"

echo "checkpoints of testnet is: "
echo -e $checkpoints
