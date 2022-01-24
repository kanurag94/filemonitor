mkdir -p /tmp/filemonitor

echo "Creating config /tmp/filemonitor/config.txt"
touch /tmp/filemonitor/config.txt

for i in {1..99}
do
    path="/tmp/filemonitor/test_file_$i.txt"
    echo "Creating $path and adding to config"
    touch "$path"
    echo "$path" >> /tmp/filemonitor/config.txt
done

echo "Starting Chaos"

# Random read
# Random write 
# Random rename
# Random delete

echo "Starting filemonitor"
x-terminal-emulator -e sudo filemonitor -f "/tmp/filemonitor/config.txt"
