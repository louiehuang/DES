#include"table.h"
#include<string>
char * HexToBi(char *hexArray);
char * toUpper(char * src);
char * BiToHex(char *biArray);

char *DES(char *BiMsg, char *BiKey, int mode);
void generateSubKeys(char * BiKey, char subKey[16][49]);
void LeftShift(char * arr, int n);
void Reverse(char *arr, int begin, int end);
void InitialPermutation(char * BiMsg);


int main() {
	//char方便输出，实际计算可用bool类型(flase不会输出)
	char HexMsg[17] = "0123456789ABCDEF";
	char HexKey[17]  = "133457799bbcdff1";
	//cout<<"Input Message: "; cin>>HexM;
	cout<<"Plaintext M: "<<HexMsg<<endl;
	char *BiMsg = HexToBi(HexMsg);
	cout<<"M in Binary: "<<BiMsg<<endl;

	//cout<<"Input Key: "; cin>>HexK;
	cout<<"Secret Key K: "<<HexKey<<endl;
	char *BiKey = HexToBi(HexKey);
	cout<<"K in Binary: "<<BiKey<<endl;
	cout<<endl;
	
	char *CipherMsg = DES(BiMsg, BiKey, 0);
	cout<<"Encrypted M in Binary: "<<CipherMsg<<endl;
	cout<<"Encrypted M: "<<BiToHex(CipherMsg)<<endl;

	char *PlainMsg = DES(CipherMsg, BiKey, 1);
	cout<<"Decrypted M in Binary: "<<PlainMsg<<endl;
	cout<<"Decrypted M: "<<BiToHex(PlainMsg)<<endl;

	return 0;
}


//初始置换
void InitialPermutation(char * BiMsg) {
	//需要复制一份原数组，否则在期间的改变会使得替换的元素发生改变
	char * BiMsgCopy = new char[65];
	memcpy(BiMsgCopy, BiMsg, 65 * sizeof(char));
	for (int i = 0; i < 64; i++) {
		int index  = IPTable[i] - 1;  //-1后才是在数组中的实际下标 
		BiMsg[i] = BiMsgCopy[index];  //原数组中index对应的元素值
	}
	delete[] BiMsgCopy;
}


//DES算法
//输入：64位2进制明文，64位2进制密钥，加密解密方式(mode=0表示加密，mode=1表示解密)
//输出：加密后密文或者解密后明文
char * DES(char * BiMsg, char *BiKey, int mode) {
	/***明文初始置换***/
	InitialPermutation(BiMsg); 

	/***由1个64位密钥产生16个48位子密钥***/
	char subKey[16][49]; //16个子密钥
	generateSubKeys(BiKey, subKey);  //产生16个子密钥

	/***BiMsg分成L和R***/
	char *L = new char[33]; L[32] = '\0';
	char *R = new char[33]; R[32] = '\0';

	for (int i = 0; i < 32; i++) {
		L[i] = BiMsg[i];  //前28位为L0，后28位为R0
		R[i] = BiMsg[i + 32];
	}
	
	/***16轮迭代***/
	for (int k = 0; k < 16; k++) {  //k为迭代轮数，加密时k也为子密钥一维下标，解密时下标位16-k，即逆序
		char *RCopy = new char[33];  //期间R会改变，因此先复制一份R，用于最后的L(i) = R(i-1)赋值
		memcpy(RCopy, R, 33);

		/**扩展置换E, 将32位的R拓展成48位的ExtendedR**/
		char * ExtendedR = new char[49]; ExtendedR[48] = '\0';
		for (int i = 0; i < 48; i++) {
			int index = ExtendedETable[i] - 1;  //-1 为数组实际下标
			ExtendedR[i] = R[index];
		}
		//cout<<"扩展后R: "<<ExtendedR<<endl;

		/**将ExtendedR和subKey异或，可以另开辟一个数组内存也可以直接改ExtendedR**/
		//加密和解密时使用子密钥顺序相反，因此需要判断
		for (int i = 0; i < 48; i++) {
			char * temp = new char[65];  //temp表示当前使用的子密钥
			if (mode == 0) {  //加密
				memcpy(temp, subKey[k], 48);
			} else if (mode == 1) {  //解密
				memcpy(temp, subKey[15 - k], 48);  //加密，倒序使用子密钥
			}

			//模拟异或
			ExtendedR[i] = ExtendedR[i] == temp[i] ? '0' : '1';
		}
		//cout<<"异或后R: "<<ExtendedR<<endl;

		/**S盒变换**/
		//48位，分成8组，每组6位，每组对应1个S盒进行变换，可以直接改R
		int indexR = 0;
		for (int s = 0; s < 8; s++) {  //8个S盒
			char group[7]; group[6] = '\0'; //1组
			for (int i = 0; i < 6; i++) {
				group[i] = ExtendedR[s * 6 + i]; //6位1组
			}
			
			//16进制字符串转10进制整型
			//如一组为010001，则line="0001", colum="1000"，则x=1, y=8
			int x, y; //x为在S盒中的行下标，y为列下标
			char *line = new char[5]; line[4] = '\0';
			char *column = new char[5]; column[4] = '\0';
			line[0] = '0'; line[1] = '0'; line[2] = group[0]; line[3] = group[5]; //01即为00 01
			column[0] = group[1]; column[1] = group[2]; column[2] = group[3]; column[3] = group[4];

			//通过HexBiTable找到2进制对应的10进制（数组下标）
			bool xflag = true, yflag = true; 
			for (int i = 0; i < 16; i++) {
				xflag = true; yflag = true; 

				//找行和列，比对HexBiTable[i]和column，若相等，则column所对应的列下标即为i（间接的2进制转10进制）
				for (int j = 0; j < 4; j++) {
					if (line[j] != HexBiTable[i][j]) //不相等
						xflag = false; 
					if (column[j] != HexBiTable[i][j]) //不相等
						yflag = false; 
				}
				if (xflag == true)
					x = i;
				if (yflag == true)
					y = i;
			}
			//cout<<x<<", "<<y<<endl;

			int target = SBox[s][x][y]; //获取S盒对应行列的元素

			//target换成2进制char数组
			char *biTarget = new char[5];
			for (int i = 3, index = 0; i >= 0; i--, index++) {
				biTarget[index] = target & (1 << i) ? '1' : '0';
			}
			biTarget[4] = '\0';
			// cout<<biTarget<<endl;

			for (int i = 0; i < 4; i++) {
				R[indexR] = biTarget[i];
				indexR++;
			}
		}

		//cout<<"S盒后R: "<<R<<endl; //S盒变换后

		//置换P
		char *SR = new char[33];
		memcpy(SR, R, 33);
		for (int i = 0; i < 32; i++) {
			int index = PTable[i] - 1; //下标
			R[i] = SR[index];
		}
		//cout<<"P置换后R: "<<R<<endl; //P置换后

		//L 异或 R 得到本轮最终的R
		for (int i = 0; i < 32; i++) {
			R[i] = R[i] == L[i] ? '0' : '1';
		}

		//开始前的R复制给L，即L(i) = R(i-1)，得到本轮最终的L
		memcpy(L, RCopy, 33);

		//cout<<"L"<<(k+1)<<": "<<L<<endl;
		//cout<<"R"<<(k+1)<<": "<<R<<endl;
		//cout<<endl;
	}

	
	/***32位互换，即(R16, L16)***/
	char *RLChange = new char[65];
	for(int i = 0; i < 32; i++) {
		RLChange[i] = R[i];
		RLChange[i + 32] = L[i];
	}
	RLChange[64] = '\0';

	//cout<<RLChange<<endl;

	/***逆初始置换***/
	char *Cipher = new char[65]; Cipher[64] = '\0';
	for(int i = 0; i < 64; i++) {
		int index = RIPTable[i] - 1; //-1 下标
		Cipher[i] = RLChange[index];
	}
	//cout<<Cipher<<endl;

	return Cipher;
}


//64位密钥产生16个48位子密钥
void generateSubKeys(char * BiKey, char subKey[16][49]) {
	char * realKey = new char[57]; realKey[56] = '\0'; //56位有效密钥	

	/**置换选择1，64位中选择56位得到实际使用的56位密钥**/
	for(int i = 0; i < 56; i++) {
		int index = PC1Table[i] - 1; //-1后才是在数组中的实际下标 
		realKey[i] = BiKey[index];
	}
	//cout<<realKey<<endl;

	//得到C和D
	char *C = new char[29]; C[28] = '\0';
	char *D = new char[29]; D[28] = '\0';
	for (int i = 0; i < 28; i++)
		C[i] = realKey[i];
	for (int i = 0, j = 28; i < 28; i++, j++)
		D[i] = realKey[j];
	//cout<<"C0: "<<C<<endl;
	//cout<<"D0: "<<D<<endl;

	/**产生16个子密钥**/
	for (int k = 0; k < 16; k++) {
		//左移
		LeftShift(C, LeftShiftTable[k]);
		LeftShift(D, LeftShiftTable[k]);
		char * CDCombine = new char[57];  CDCombine[56] = '\0';
		for(int i = 0; i < 28; i++) { //C和D合并
			CDCombine[i] = C[i];
			CDCombine[i+28] = D[i];
		}
		//cout<<CDCombine<<endl;

		/*置换选择2，从56位的CDCombine选择48位的subKey出来*/
		for(int i = 0; i < 48; i++) {
			int index  = PC2Table[i] - 1; //-1后才是在数组中的实际下标 
			subKey[k][i] = CDCombine[index];
		}

		subKey[k][48] = '\0';
		//cout<<"Key"; printf("%2d", k+1);
		//cout<<":	"<<subKey[k]<<endl;
	}
}


/***循环左移n位，复杂度0(n)，通过三次逆序实现***/
void LeftShift(char * arr, int n) {
	Reverse(arr, 0, n - 1); //逆序前n位
	Reverse(arr, n, 28 - 1); //逆序后所有位
	Reverse(arr, 0, 28 - 1); //逆序所有位
}


/***逆序排列***/
void Reverse(char *arr, int begin, int end) {
	char temp;
	for ( ; begin < end; begin++, end--) {
		temp = arr[end];
		arr[end] = arr[begin];
		arr[begin] = temp;
	}
}


/***16进制数组转2进制数组(16元素)，输入M和K时使用(64位)以及S盒变换时使用(4位)***/
char * HexToBi(char *hexArray) {
	toUpper(hexArray); //小写转大写
	char * biArray = new char[65];
	int index = 0;

    char *p = hexArray;
    while (*p) {  //字符串不结束就循环
		string temp;
        if (*p>='0' && *p <='9') {  //数字
			temp = HexBiTable[*p - 48];
		} else if (*p>='A' && *p <='F') {  //A~F字符
			temp = HexBiTable[*p - 65 + 10];
		}
		for (int i = 0; i < 4; i++, index++) {
			biArray[index] = temp[i];
		}
        p++; //指针后指，准备处理下一个字母
    }

	biArray[index] = '\0';
	return biArray;
}


/***小写转大写***/
char * toUpper(char * src) {
    char *p=src;
    while (*p) {  //字符串不结束就循环
        if (*p>='a' && *p <='z') //判断小写字母
            *p-=32; //转大写
        p++; //指针后指，准备处理下一个字母
    }
    return src; //返回修改后的字符串首地址
}


/***2进制转16进制，4位1组，64位***/
char * BiToHex(char *biArray) {
	char *result = new char[17]; result[16] = '\0';
	char temp[5]; temp[4] = '\0'; //4位1组
	int index = 0;
	for (int i = 0; i < 16; i++) {  //16轮，每轮转4位
		int j = 0;
		for (j = 0; j < 4; j++) {  //每轮4位
			temp[j] = biArray[i * 4 + j];
		}

		//temp = "1000"
		string str = temp; //char赋值给string，方便用于string比较字符串是否相等
		int mark; //在HexBiTable中下标
		for (int k = 0; k < 16; k++) {
			if (str.compare(HexBiTable[k]) == 0) {  //相同
				mark = k;
			}
		}

		if (mark >= 0 && mark <= 9) {
			result[i] = mark + 48;
		} else if (mark >= 10 && mark <=15) {	
			result[i] = mark - 10 + 65;
		}
	}
	return result;
}
