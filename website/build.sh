#!/bin/sh

# create some temp files files
tmpfile1=`tempfile`
tmpfile2=`tempfile`

index_content="src/index.splash.html
		src/index.features.html
		src/index.news.html
		src/index.downloads.html
		src/index.support.html"
installation_content="src/installation.content.html"
faq_content="src/faq.test.html
		src/faq.needdbus.html
		src/faq.gdb.html
		src/faq.symbolstripping.html
		src/faq.defaultregions.html
		src/faq.dumpstatic.html
		src/faq.maxstacksize.html
		src/faq.binindirectdump.html
		src/faq.rlimit.html"

# replace the $ROOT$ variable in $1, store in $2
REPLACE_ROOT()
{
	sed -e 's/\$ROOT\$/\/minicoredumper\//g' $1 > $2
}

# replace the $FAQHEADID$ ($1) and $FAQCOLLID$ ($2) variables in $3,
# store in $4
REPLACE_FAQID()
{
	sed -e "s/\\\$FAQHEADID\\\$/$1/g" -e "s/\\\$FAQCOLLID\\\$/$2/g" $3 > $4
}

REPORT()
{
	echo "created $1"
}

# create main page
cat src/template/root.head.html $index_content src/template/root.tail.html > $tmpfile1
REPLACE_ROOT $tmpfile1 root/index.html
REPORT root/index.html

# create installation page
cat src/template/root.head.html $installation_content src/template/root.tail.html > $tmpfile1
REPLACE_ROOT $tmpfile1 root/installation.html
REPORT root/installation.html

# create faq page
cat src/template/root.head.html > $tmpfile1
cat src/template/faq.head.html >> $tmpfile1
for item in $faq_content; do
	faqid=`echo $item | cut -d . -f 2`
	faqheadid="head$faqid"
	faqcollid="coll$faqid"

	cat src/template/faq.qahead.html >> $tmpfile1

	REPLACE_FAQID $faqheadid $faqcollid src/template/faq.qhead.html $tmpfile2
	cat $tmpfile2 >> $tmpfile1

	head -n 1 $item >> $tmpfile1

	cat src/template/faq.qtail.html >> $tmpfile1

	REPLACE_FAQID $faqheadid $faqcollid src/template/faq.ahead.html $tmpfile2
	cat $tmpfile2 >> $tmpfile1

	tail -n +2 $item >> $tmpfile1

	cat src/template/faq.atail.html >> $tmpfile1

	cat src/template/faq.qatail.html >> $tmpfile1
done
cat src/template/faq.tail.html >> $tmpfile1
cat src/template/root.tail.html >> $tmpfile1
REPLACE_ROOT $tmpfile1 root/faq.html
REPORT root/faq.html

# create man pages
for manpage in `find ../src -type f | grep '\.[0-9]$'`; do
	man_basename=`basename $manpage`
	man_section=`echo $man_basename | rev | cut -c 1`
	htmlpage="root/man/man${man_section}/${man_basename}.html"

	# create basic html version of manpage
	man2html -r $manpage > $tmpfile1

	# find the first and last lines of content
	last_line=`grep -n 'The DiaMon Workgroup' $tmpfile1 | tail -n 1 | \
			awk -F : '{print $1}'`
	first_line=`grep -n 'lbAB' $tmpfile1 | head -n 1 | \
			awk -F : '{print $1}'`

	# make sure we have first and last lines
	if [ -z "$first_line" -o -z "$last_line" ]; then
		echo "error processing $manpage" 1>&2
		continue
	fi

	# extract content
	head -n $last_line $tmpfile1 | tail -n +$first_line > $tmpfile2

	# identify external man pages
	missing_list=""
	for item in `grep -i href= $tmpfile2 | grep 'man[0-9]' | \
			sed -e 's/\.html".*//' -e 's/.*\///' | \
			grep '\.[0-9]$'`; do
		if [ -z "`find ../src -type f -name $item`" ]; then
			missing_list="$missing_list $item"
		fi
	done

	# replace all missing ../man links with links to external pages
	for item in $missing_list; do
		cmd=`echo $item | sed -e 's/\.[0-9]//'`
		sect=`echo $item | rev | cut -c 1`
		sed -e "s/\.\.\(\/man${sect}\/${cmd}\.${sect}\.html\)/http:\/\/man7.org\/linux\/man-pages\1/" $tmpfile2 > $tmpfile1
		mv $tmpfile1 $tmpfile2
	done

	# identify external files
	missing_list=""
	for item in `grep -i href= $tmpfile2 | grep 'file://' | \
			sed -e 's/.*file:\/\///' -e 's/".*//' \
			-e 's/.*\///'`; do
		srcfile=`find ../src -type f -name $item | head -n 1`
		if [ ! -z "$srcfile" ]; then
			missing_list="$missing_list $srcfile"
		else
			echo "error finding $item" 1>&2
		fi
	done

	# replace all missing file:// links with links to local files
	sed -e 's/="file:\/\/[^"]*\//="$ROOT$man\//' $tmpfile2 > $tmpfile1
	mv $tmpfile1 $tmpfile2

	# create directory for html manpage
	mkdir -p `dirname $htmlpage`

	# copy over local files to manpage root directory
	for item in $missing_list; do
		lfile=`echo $item | sed -e 's/.*\///'`
		cp $item root/man/
		REPORT root/man/$lfile
	done

	# create integrated html manpage
	cat src/template/root.head.html $tmpfile2 src/template/root.tail.html > $tmpfile1
	REPLACE_ROOT $tmpfile1 $htmlpage
	REPORT $htmlpage
done

# cleanup the temp files
rm -f $tmpfile1 $tmpfile2
