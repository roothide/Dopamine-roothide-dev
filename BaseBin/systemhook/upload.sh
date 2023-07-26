set -e

PROJECT_NAME=systemhook.dylib
DEVICE=root@localhost
PORT=2223

make
ssh $DEVICE -p $PORT "rm -rf /tmp/$PROJECT_NAME"
scp -P$PORT ./$PROJECT_NAME $DEVICE:/tmp/$PROJECT_NAME
ssh $DEVICE -p $PORT "/basebin/jbctl rebuild_trustcache"