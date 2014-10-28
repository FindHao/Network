for i in *
do
if test -f $i
then
iconv -f gbk -t utf8 $i -o /tmp/$i.new
cp /tmp/$i.new $i
rm /tmp/$i.new
fi
done

