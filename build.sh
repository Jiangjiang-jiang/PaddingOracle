if [ $DOCKER ];then
	cd /work/aes_enc
	cmake .
	make
	cd /work/aes_dec
	cmake .
	make
else
	docker build -t padding_oracle .
	docker run --rm -v $PWD:/work padding_oracle
	docker image rm padding_oracle
fi
