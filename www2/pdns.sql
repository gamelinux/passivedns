-- MySQL dump 10.13  Distrib 5.5.44, for debian-linux-gnu (i686)
--
-- Host: localhost    Database: pdns
-- ------------------------------------------------------
-- Server version	5.5.44-0ubuntu0.14.04.1-log

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `pdns`
--

DROP TABLE IF EXISTS `pdns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pdns` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `QUERY` varchar(255) NOT NULL DEFAULT '',
  `MAPTYPE` varchar(10) NOT NULL DEFAULT '',
  `RR` varchar(10) NOT NULL DEFAULT '',
  `ANSWER` varchar(255) NOT NULL DEFAULT '',
  `TTL` int(10) NOT NULL DEFAULT '0',
  `COUNT` bigint(20) unsigned NOT NULL DEFAULT '1',
  `FIRST_SEEN` datetime NOT NULL,
  `LAST_SEEN` datetime NOT NULL,
  `asn` int(8) DEFAULT NULL,
  PRIMARY KEY (`ID`),
  UNIQUE KEY `MARQ` (`MAPTYPE`,`ANSWER`,`RR`,`QUERY`),
  KEY `query_idx` (`QUERY`),
  KEY `answer_idx` (`ANSWER`),
  KEY `LAST_SEEN` (`LAST_SEEN`)
) ENGINE=MyISAM AUTO_INCREMENT=55044 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tlds`
--

DROP TABLE IF EXISTS `tlds`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tlds` (
  `id` bigint(32) unsigned NOT NULL AUTO_INCREMENT,
  `tld` varchar(512) CHARACTER SET utf8 NOT NULL,
  `tick` tinyint(1) unsigned NOT NULL DEFAULT '0',
  `length` int(4) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tld` (`tld`(333)),
  KEY `length` (`length`)
) ENGINE=MyISAM AUTO_INCREMENT=7747 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-08-27 23:19:52
