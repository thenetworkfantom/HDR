cd modules/kalipso
echo "To close all unused redis servers, run slips with --killall"
file="../../running_slips_info.txt"

declare -a open_redis_servers=()
declare -a ports=()

while IFS= read -r line
do
    if [[ ${line} =~ "Date" ]] || [[ ${line} =~ "
     continue
    fi
    IFS=','
    read -ra splitted_line <<< "$line"

    open_redis_servers[${

    ports[${
done < "$file"

if [[ ${
  echo "You have 0 open redis-servers to use. Make sure you run slips first"
  exit 1

elif [[ ${
  port_to_use=${ports[0]}

elif [[ ${
    echo "You have ${
    ctr=1
    for value in "${open_redis_servers[@]}"
        do
             echo "[$ctr] $value - port ${ports[ctr-1]}"
             let ctr=ctr+1
        done
    read index
    let index=index-1

    port_to_use=${ports[index]}
fi

node kalipso -l 2000 -p ${port_to_use}
