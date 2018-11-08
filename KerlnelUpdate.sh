#!/bin/bash

read -p " Ingrese el tipo de base de datos: " TYPEDB
read -p " Ingrese Usuario de instancia: " USER
read -p " Ingrese Clave usuario de instancia:  " PASS
read -p " Ingrese IP de la instancia central  " IP

if [ "$TYPEDB" == "DB2" ] || [ "$TYPEDB" == "db2" ] || [ "$TYPEDB" == "ORACLE" ] || [ "$TYPEDB" == "oracle" ] || [ "$TYPEDB" == "SYBASE" ] || [ "$TYPEDB" == "sybase" ] ;then
	read -p " Ingrese Usuario de base de datos:   " USERDB
	read -p " Ingrese clave usuario base de datos   " PASSDB
	read -p " Ingrese IP de la base de datos   " IPDB
fi
if [ "$TYPEDB" == "SYBASE" ] || [ "$TYPEDB" == "sybase" ] ;then
	read -p " Ingrese clave del usuario "SAPSA" de la base de datos   " pass_sapsa
fi
read -p " Ingrese SID del sistema en letra Mayuscula  " SID
read -p " Ingrese numero de la instancia ( 2 digitos )  " INSTANCE
read -p " Ingrese nombre completo de la instancia (Ej: 'DVEBMGS01' )  " NAME_INSTANCE
read -p " Ingrese ruta completa de donde estan alojados los nuevos medios (En servidor SAP-RHEL)   " RUTA_FILES_NEW
read -p " Ingrese nombre del usuario superadministrador del servidor de instancia   " ROOT
read -p " Ingrese clave de usuario superadministrador   " ROOT_PASS

while true;do
read -p "This systems is Dual Stack?" yn
case $yn in
[Yy]* )
type_system="OK"
break;;
[Nn]* ) 
type_system="FAIL"
break;;
* ) echo "Please answer yes or no.";;
esac
done

while true;do
read -p "El puerto de comunicacion por SSH al servidor de instancia central es 22?" yn
case $yn in
[Yy]* )
port_con_ic="22"
break;;
[Nn]* )
read -p " Porfavor ingrese el numero de puerto por el cual se realizara la conexion SSH  " port_con_ic
break;;
* ) echo "Please answer yes or no.";;
esac
done

while true;do
read -p "El puerto de comunicacion por SSH al servidor de base de datos es 22?" yn
case $yn in
[Yy]* )
port_con_db="22"
break;;
[Nn]* )
read -p " Porfavor ingrese el numero de puerto por el cual se realizara la conexion SSH  " port_con_db
break;;
* ) echo "Please answer yes or no.";;
esac
done


status1="FAIL";
status2="FAIL";
status3="FAIL";
status3_1="FAIL";
status4="FAIL";
status5="FAIL";
status6="FAIL";
status7="FAIL";
status8="FAIL";
status9="FAIL";
status10="FAIL";
status11="FAIL";
status11_0="FAIL";
status11_1="FAIL";
status12="FAIL";
status13="FAIL";

while true; do
    read -p "Do you wish to kernel update?" yn
    case $yn in
        [Yy]* ) 
	SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "exit" 2>&1 >/dev/null && status1="OK" || status1="FAIL"
	if [ "$TYPEDB" == "ORACLE" ] || [ "$TYPEDB" == "oracle" ] || [ "$TYPEDB" == "DB2" ] || [ "$TYPEDB" == "db2" ] || [ "$TYPEDB" == "SYBASE" ] || [ "$TYPEDB" == "sybase" ];then
		SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db "exit" 2>&1 >/dev/null && status2="OK" || status2="FAIL"
	fi
	if [ "$TYPEDB" == "HANA" ] || [ "$TYPEDB" == "hana" ];then
		status2="OK"
	fi
	if [ "$status1" == "OK" ] && [ "$status2" == "OK" ];then
		SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "test -e /usr/sap/$SID/$NAME_INSTANCE/work/sapcpe.log" 2>&1 >/dev/null && status3="OK" || status3="FAIL"
		if [ "$status3" == "OK" ];then
			RUTA_SAPCPE="/usr/sap/$SID/$NAME_INSTANCE/work/sapcpe.log"
			out=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cat $RUTA_SAPCPE | grep source");
			sapcpe_validate=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cat $RUTA_SAPCPE | tail -11");
			sapcpe_ini=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cat $RUTA_SAPCPE | head -1");
			SUBSTRING=$out;
			leng_fin=${#SUBSTRING};
			leng_ini=8;
			rute=${SUBSTRING:$leng_ini:($leng_fin-$leng_ini)};
		else
			while [ "$status3_1" == "FAIL" ]
			do
				read -p " Ingrese manualmente la ruta donde se encuentran alojados los binarios del kernel, ya que el log sapcpe no fue encontrado    " rute
				SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "test -e $rute" 2>&1 >/dev/null && status3_1="OK" || status3_1="FAIL"
			done
		fi
	
		rute_home=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "pwd")
		SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "disp+work > $rute_home/kernel_last" 2>&1 >/dev/null && status4="OK" || status4="FAIL"
		kernel_ini=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cat $rute_home/kernel_last | awk ' FNR == 8 { print \$4 }'")
		path_ini=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cat $rute_home/kernel_last | awk ' FNR == 20 { print \$3 } '")
		SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "rm -f $rute_home/kernel_last"
		echo $rute
		echo
		echo "COMPROBANDO ESPACIO DISPONIBLE: "
		echo
		free_space_client=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cd $rute && "df -Pg . | tail -1 | awk '{print $4}'"");
		GIGA="1000000000";
		test -e $RUTA_FILES_NEW 2>&1 >/dev/null && status5="OK" || status5="FAIL"

		while [ "$status5" == "FAIL" ]
		do
			read -p " No existe la ruta suministrada de los nuevos binarios de kernel, Porfavor ingrese nuevamente la ruta" RUTA_FILES_NEW
			test -e $RUTA_FILES_NEW 2>&1 >/dev/null && status5="OK" || status5="FAIL"
		done

		cd $RUTA_FILES_NEW
		space_total_files=$(ls -lSrH | awk '{ total += $5 }; END { print total }');
		space_total_files=$(awk '{print $1/$2}' <<<"$space_total_files $GIGA");
                space_missing_files=$(awk '{print $1-$2}' <<<"$free_space_client $space_total_files");
		cero_value="0"
		if (( $(awk 'BEGIN {print ("'$space_missing_files'" > "'$cero_value'")}') )); then
			status6="OK"
		else
			status6="FAIL"
		fi
		
		if [ "$status6" == "OK" ];then
			echo
			echo "SE COMPROBO QUE HAY ESPACIOS DISPONIBLE PARA LA TRANSFERENCIA DE NUEVOS BINARIOS, SE CONTINUARA CON LA EJECUCION"
			echo
			echo "BAJANDO SISTEMA SAP"
        	        echo
			sap_change "DOWN"
			if [ "$status7" == "OK" ];then
				echo "LIMPIANDO SEMAFOROS"
				SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic " cleanipc $INSTANCE remove" 2>&1 >/dev/null && status8="OK" || status8="FAIL"
				if [ "$status8" == "OK" ];then
			        	echo
				        echo "RUTA KERNEL :"
        			        echo $rute;
                			echo
			                if [ "$TYPEDB" == "ORACLE" ] || [ "$TYPEDB" == "oracle" ];then
        			       	        echo "BAJANDO BASE DE DATOS ORACLE"
       	        			        echo
						shutdown_db "ORACLE"
   	        			fi
			                if [ "$TYPEDB" == "DB2" ] || [ "$TYPEDB" == "db2" ];then
			       	                echo "BAJANDO BASE DE DATOS DB2"
	                		        echo
						shutdown_db "DB2"
			       	        fi
			                if [ "$TYPEDB" == "SYBASE" ] || [ "$TYPEDB" == "sybase" ];then
			                        echo "BAJANDO BASE DE DATOS SYBASE"
                       				echo
						shutdown_db "SYBASE"
			    		fi
					if [ "$TYPEDB" == "HANA" ] || [ "$TYPEDB" == "hana" ];then
						status9="OK"
					fi
					if [ "$status9" == "OK" ];then
						echo "SE INICIARA LA EJECUCION: "
						echo
						filename_kernel=$(echo "$rute" | sed "s/.*\///");
						filename=$(echo "$RUTA_FILES_NEW" | sed "s/.*\///");
						newrute=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic " cd $rute && cd .. && pwd ");
						echo "COMENZANDO TRANSFERENCIA DE ARCHIVOS KERNEL NUEVO"
						echo
						SSHPASS=$PASS sshpass -e $pass scp -P $port_con_ic -pr $RUTA_FILES_NEW $USER@$IP:$newrute 2>&1 >/dev/null && status10="OK" || status10="FAIL"
						if [ "$status10" == "OK" ];then
							DATE=`date +%Y-%m-%d`;
							echo "REALIZANDO BACKUP DE ANTIGUOS BINARIOS KERNEL"
							SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cd $newrute && mv $filename_kernel '$filename_kernel'_'$DATE'";
							SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic " cd $newrute && mv $filename $filename_kernel ";

                                                        if [ "$TYPEDB" == "HANA" ] || [ "$TYPEDB" == "hana" ];then
								echo "APLICANDO PERMISOS ROOT"
                                                                SSHPASS=$ROOT_PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $ROOT@$IP -p $port_con_ic "cd $rute && ./saproot.sh $SID" 2>&1 >/dev/null && status11_0="OK" || status11_0="FAIL"
                                                        fi
                                                        if [ "$TYPEDB" == "ORACLE" ] || [ "$TYPEDB" == "oracle" ];then
								echo "APLICANDO PERMISOS ROOT"
                                                                SSHPASS=$ROOT_PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $ROOT@$IP -p $port_con_ic " cd $rute && ./saproot.sh $SID" 2>&1 >/dev/null && status11_0="OK" || status11_0="FAIL";
                                                                SSHPASS=$ROOT_PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $ROOT@$IP -p $port_con_ic " cd $rute && ./oraroot.sh $SID";
                                                        fi
                                                        if [ "$TYPEDB" == "DB2" ] || [ "$TYPEDB" == "db2" ];then
								echo "APLICANDO PERMISOS ROOT"
                                                                SSHPASS=$ROOT_PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $ROOT@$IP -p $port_con_ic " cd $rute && ./saproot.sh $SID" 2>&1 >/dev/null && status11_0="OK" || status11_0="FAIL"
                                                        fi
                                                        if [ "$TYPEDB" == "SYBASE" ] || [ "$TYPEDB" == "sybase" ];then
								echo "APLICANDO PERMISOS ROOT"
                                                                SSHPASS=$ROOT_PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $ROOT@$IP -p $port_con_ic " cd $rute && ./saproot.sh $SID" 2>&1 >/dev/null && status11_0="OK" || status11_0="FAIL"
                                                        fi
							if [ "$status11_0" == "FAIL" ];then
								echo "ERROR EN CONEXION DIRECTA CON USUARIO SUPERADMINISTRADOR, NO PUDIERON SER EJECUTADOS LOS SCRIPTS INCLUIDOS EN LOS NUEVOS BINARIOS DE KERNEL ---> EJECUTAR MANUALMENTE "
							else
								echo "SCRIPTS INCLUIDOS EN LOS BINARIOS DEL KERNEL, FUERON EJECUTADOS SATISFACTORIAMENTE"
							fi

							if [ "$TYPEDB" == "ORACLE" ] || [ "$TYPEDB" == "oracle" ];then
								echo "INICIANDO BASE DE DATOS ORACLE"
								echo
								up_db "ORACLE"
							fi
				                	if [ "$TYPEDB" == "DB2" ] || [ "$TYPEDB" == "db2" ];then
								echo "INICIANDO BASE DE DATOS DB2"
								echo
								up_db "DB2"
					                fi
							if [ "$TYPEDB" == "SYBASE" ] || [ "$TYPEDB" == "sybase" ];then
					                        echo "INICIANDO BASE DE DATOS SYBASE"
				        	                echo
								up_db "SYBASE"
					                fi
							if [ "$TYPEDB" == "HANA" ] || [ "$TYPEDB" == "hana" ];then
								status11="OK"
							fi
							if [ "$status11" == "OK" ];then
								echo
								echo
								echo "INICIANDO SAP"
								echo
								sap_change "UP"
								if [ "$status12" == "OK" ];then
									if [ "$status3" == "OK" ];then
										sapcpe_fin=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cat $RUTA_SAPCPE | head -1");
										if [ "$sapcpe_ini" == "$sapcpe_fin" ];then
											echo "El sacpe no se ejecuto correctamente para realizar la copia de kernel en las instancias, porfavor revise"
										fi
										if [ "$sapcpe_ini" != "$sapcpe_fin" ];then
											SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "disp+work > $rute_home/kernel_current"
											kernel_out=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cat $rute_home/kernel_current | awk ' FNR == 8 { print \$4 }'")
											path_out=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cat $rute_home/kernel_current | awk ' FNR == 20 { print \$3 } '")
											SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "rm -f $rute_home/kernel_current"
											echo
											echo
											echo "NUESTROS ARCHIVOS KERNEL TRANSFERIDOS SATISFACTORIAMENTE";
											echo
											echo "HORA DE ACTUALIZACION SAPCPE :  "
											echo "$sapcpe_fin"
											echo
											echo "RESULTADO EJECUCION SAPCPE: "
											echo "$sapcpe_validate"
											echo
											echo "KERNEL ACTUALIZO DE LA VERSION $kernel_ini CON PARCHE $path_ini A LA VERSION $kernel_out CON PARCHE $path_out"
										fi
									else
										echo "RECUERDE QUE AL NO SER ENCONTRADO SAPCPE.LOG, DEBE EJECUTAR EL SCRIPT LAS VECES QUE SEAN NECESARIAS PARA REALIZAR LA COPIA DEL KERNEL EN CADA UNA DE LAS RUTAS DE INSTANCIA QUE SE VAYAN INGRESANDO MANUALMENTE"
										echo
										SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "disp+work > $rute_home/kernel_current"
                                                                                kernel_out=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cat $rute_home/kernel_current | awk ' FNR == 8 { print \$4 }'")
                                                                                path_out=$(SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cat $rute_home/kernel_current | awk ' FNR == 20 { print \$3 } '")
                                                                                SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "rm -f $rute_home/kernel_current"
                                                                                echo
                                                                                echo
                                                                                echo "NUESTROS ARCHIVOS KERNEL TRANSFERIDOS SATISFACTORIAMENTE";
                                                                                echo
                                                                                echo "HORA DE ACTUALIZACION SAPCPE : "
                                                                                echo "$sapcpe_fin"
                                                                                echo
                                                                                echo "RESULTADO EJECUCION SAPCPE: "
                                                                                echo "$sapcpe_validate"
                                                                                echo
                                                                                echo "KERNEL ACTUALIZO DE LA VERSION $kernel_ini CON PARCHE $path_ini A LA VERSION $kernel_out CON PARCHE $path_out"
									fi
								else
									echo "ERROR SUBIENDO INSTANCIA SAP, PORFAVOR SUBIR MANUALMENTE"
								fi
							else
								echo "ERROR SUBIENDO LA BASE DE DATOS, PORFAVOR SUBIR MANUALMENTE LA BASE DE DATOS Y INSTANCIA SAP"
							fi
						else
                                                        if [ "$TYPEDB" == "ORACLE" ] || [ "$TYPEDB" == "oracle" ];then
								up_db "ORACLE"
                                                        fi
                                                        if [ "$TYPEDB" == "DB2" ] || [ "$TYPEDB" == "db2" ];then
								up_db "DB2"
                                                        fi
                                                        if [ "$TYPEDB" == "SYBASE" ] || [ "$TYPEDB" == "sybase" ];then
                                                                up_db "SYBASE"
                                                        fi

							sap_change "UP"

							echo "ERROR EN LA TRANSFERENCIA DE LOS NUEVOS BINARIOS, PORFAVOR REVISAR CREDENCIALES O RUTA CORRECTA DE BINARIOS";
						fi
					else
						if [ "$TYPEDB" == "ORACLE" ] || [ "$TYPEDB" == "oracle" ];then
							sap_change "UP"
							echo " ERROR BAJANDO LA BASE DE DATOS, PORFAVOR REVISAR EL FUNCIONAMIENTO DEL CLIENTE SQLPLUS O CREDENCIALES DE CONEXION A LA BASE DE DATOS";
						fi
                                                if [ "$TYPEDB" == "DB2" ] || [ "$TYPEDB" == "db2" ];then
							sap_change "UP"
	                                                echo " ERROR BAJANDO LA BASE DE DATOS, PORFAVOR REVISAR EL FUNCIONAMIENTO DEL CLIENTE DB2 O CREDENCIALES DE CONEXION A LA BASE DE DATOS";
                                                fi
                                                if [ "$TYPEDB" == "SYBASE" ] || [ "$TYPEDB" == "sybase" ];then
							sap_change "UP"
        	                                        echo " ERROR BAJANDO LA BASE DE DATOS, PORFAVOR REVISAR EL FUNCIONAMIENTO DEL CLIENTE ISQL O REDENCIALES DE CONEXION A LA BASE DE DATOS";
                                                fi
					fi
				else
					echo "ERROR EN LA LIMPIEZA DE SEMAFOROS,PORFAVOR REVISE"
				fi
			else
				sap_change "UP"
				echo "ERROR BAJANDO INSTANCIA SAP, PORFAVOR REVISE"
			fi
		else
			space_missing=$(awk '{print $1-$2}' <<<"$free_space_client $space_total_files");
			echo "NO HAY ESPACIOS DISPONIBLE PARA LA TRANSFERENCIA DE ARCHIVOS, HACEN FALTAN $space_missing GB -- > PORFAVOR ASIGNAR ESPACIO"
		fi
	else
		echo "ERROR EN CREDENCIALES DE CONEXION, PORFAVOR REVISAR"
	fi

	# -----------  FUNCIONES -----------------

	##Bajar base de datos
	shutdown_db(){
		if [ "$1" == "ORACLE" ];then
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db " echo 'SHUTDOWN IMMEDIATE;' | sqlplus -S / as sysdba && exit" 2>&1 >/dev/null && status9="OK" || status9="FAIL"
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db " ipcs -s | grep $USERDB | awk ' { print $2 } ' | xargs ipcrm sem && ps -ef | grep sap | grep $USERDB | awk '{print $ 2}' | xargs kill -9 " 2>&1 >/dev/null
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db " cd && lsnrctl stop " 2>&1 >/dev/null 
		elif [ "$1" == "DB2" ];then
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db " db2 connect reset && db2 deactivate db $SID && db2 force applications all && db2 terminate && db2stop " 2>&1 >/dev/null && status9="OK" || status9="FAIL"
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db " ipcs -s | grep $USERDB | awk ' { print $2 } ' | xargs ipcrm sem && ps -ef | grep sap | grep $USERDB | awk '{print $ 2}' | xargs kill -9 " 2>&1 >/dev/null
		elif [ "$1" == "SYBASE" ];then
			RUTE_sql=$(SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db " pwd ");
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db " echo "SHUTDOWN" >> $RUTE_sql/code.sql && echo "go" >> $RUTE_sql/code.sql ";
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db << EOF 2>&1 >/dev/null
isql -S'$SID' -U'sapsa' -P'$pass_sapsa' -X -w2000 -i'$RUTE_sql/code.sql';
rm -f $RUTE_sql/code.sql
EOF
			status9="OK"
		fi
	}

	##Subir base de datos
	up_db(){
		if [ "$1" == "ORACLE" ];then
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db " cd & lsnrctl start " 2>&1 >/dev/null
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db " echo 'STARTUP;' | sqlplus -S / as sysdba" 2>&1 >/dev/null && status11="OK" || status11="FAIL"
		elif [ "$1" == "DB2" ];then
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db " db2start && db2 activate db $SID && db2 connect to $SID " 2>&1 >/dev/null && status11="OK" || status11="FAIL"
		elif [ "$1" == "SYBASE" ];then
			SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db "test -e /sybase/$SID/ASE-15_0/install" 2>&1 >/dev/null && status11_1="OK" || status11_1="FAIL"
			if [ "$status11_1" == "OK" ];then
				SSHPASS=$PASSDB sshpass -e $pass ssh -T -q -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db <<EOF 2>&1 >/dev/null
cd /sybase/$SID/ASE-15_0/install
startserver -fRUN_$SID
startserver -fRUN_$SID'_BS'
EOF
				status11="OK"
			else
				SSHPASS=$PASSDB sshpass -e $pass ssh -T -q -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db "test -e /sybase/$SID/ASE-16_0/install" 2>&1 >/dev/null && status11_1="OK" || status11_1="FAIL"
				if [ "$status11_1" == "OK" ];then
					SSHPASS=$PASSDB sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USERDB@$IPDB -p $port_con_db <<EOF 2>&1 >/dev/null
cd /sybase/$SID/ASE-16_0/install
startserver -fRUN_$SID
startserver -fRUN_$SID'_BS'
EOF
					status11="OK"
				else
					echo "NO EXISTE EL DIRECTORIO "INSTALL" DE LA BASE DE DATOS , POR LO TANTO NO SE PUEDEN EJECUTAR LOS SCRIPTS DE SUBIDA DE BASE DE DATOS EN SYBASE"
					status11="FAIL"
				fi
			fi
		fi
	}

	## Bajar o Subir Instancia SAP
	sap_change(){
		if [ "$1" == "DOWN" ];then
			if [ "$type_system" == "FAIL" ];then
				SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cd $rute && stopsap R3" 2>&1 >/dev/null && status7="OK" || status7="FAIL"
			else
				SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cd $rute && stopsap" 2>&1 >/dev/null && status7="OK" || status7="FAIL"
			fi
		elif [ "$1" == "UP" ];then
			if [ "$type_system" == "FAIL" ];then
				SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cd $rute && startsap R3" 2>&1 >/dev/null && status12="OK" || status12="FAIL"
			else
				SSHPASS=$PASS sshpass -e $pass ssh -o "StrictHostKeyChecking no" $USER@$IP -p $port_con_ic "cd $rute && startsap" 2>&1 >/dev/null && status12="OK" || status12="FAIL"
			fi
		fi
	}

	break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done
