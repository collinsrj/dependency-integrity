dependency-integrity
=====================
## Introduction
This package allows for the generation of a database containing information on a [Maven](http://maven.apache.org/) source code repository. The goal of this is to allow the integrity of the artifacts to be determined by examining the artifacts themselves and their relationships to other entities. A copy of the schema can be seen below:

![erd](https://raw.github.com/collinsrj/dependency-integrity/master/erd.png "DB Schema for Integrity Investigation")   

The class `ie.dcu.collir24.VerifySignatures` can be executed with a path name specified as a command line argument. This will generate a [H2](http://www.h2database.com/) database. This can then be examined by any tool which supports the H2 JDBC driver. 
Each file encountered will be:

1.  Checked for a signature file. If one is present the signature will be checked and the public key information stored.
2.  If the file is a pom file, the Maven details will be extracted. It was not always possible to extract the details from Maven files; some were not valid XML, some didn't contain the required details etc.
3.  If the file is a jar file, the following were checked:
    *  was the jar signed, if so the signature was checked and details logged
    *  were sealed packages listed

Upon completing the load of data, some data quality issues were noted; it was not always possible to identify and download only the latest version. Rather than try and identify the latest version, all POM entries where there were duplicate group and artifact IDs were removed from the database by executing the following: 

```sql
ALTER TABLE DEVELOPERS  ADD FOREIGN KEY (MAVEN_POM_ID) REFERENCES MAVEN_POM(ID) on DELETE CASCADE;
ALTER TABLE JAR  ADD FOREIGN KEY (ID) REFERENCES FILE(ID) on DELETE CASCADE;
ALTER TABLE JAR_CERT_PATHS   ADD FOREIGN KEY (FILE_ID) REFERENCES FILE(ID) on DELETE CASCADE;
ALTER TABLE JAR_SEALED_PACKAGES   ADD FOREIGN KEY (FILE_ID) REFERENCES FILE(ID) on DELETE CASCADE;
ALTER TABLE MAVEN_POM   ADD FOREIGN KEY (ID) REFERENCES FILE(ID) on DELETE CASCADE;
ALTER TABLE SIGNATURE   ADD FOREIGN KEY (FILE_ID) REFERENCES FILE(ID) on DELETE CASCADE;

DELETE
FROM file
WHERE id IN
    (SELECT id
     FROM maven_pom mp1
     JOIN
       (SELECT group_id AS gid,
               artifact_id AS aid,
               count(*) AS c
        FROM maven_pom mp
        GROUP BY gid ,
                 aid HAVING c > 1) ON ISNULL(mp1.group_id,'') = ISNULL(gid, '')
     AND ISNULL(mp1.artifact_id,'') = ISNULL(aid,''));
```