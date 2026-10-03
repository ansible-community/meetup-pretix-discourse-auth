all: localecompile
LNGS:=`find pretix_discourse_auth/locale/ -mindepth 1 -maxdepth 1 -type d -printf "-l %f "`

localecompile:
	django-admin compilemessages

localegen:
	django-admin makemessages --add-location file --keep-pot -i build -i dist -i "*egg*" $(LNGS)

.PHONY: all localecompile localegen
