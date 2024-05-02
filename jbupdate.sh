DEVICE=root@iphone11.local
PORT=22

ssh $DEVICE -p $PORT "rm -rf /rootfs/var/mobile/Documents/Dopamine.tipa"
scp -P$PORT ./Dopamine/Dopamine.tipa $DEVICE:/rootfs/var/mobile/Documents/Dopamine.tipa
ssh $DEVICE -p $PORT "/var/jb/basebin/jbctl update tipa /var/mobile/Documents/Dopamine.tipa"