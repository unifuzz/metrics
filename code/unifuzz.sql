SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for bugid
-- ----------------------------
DROP TABLE IF EXISTS `bugid`;
CREATE TABLE `bugid` (
  `id` int(11) NOT NULL,
  `progname` varchar(255) NOT NULL,
  `stacktrace` varchar(10000) DEFAULT NULL,
  `vulntype` varchar(255) DEFAULT NULL,
  `CVE` varchar(255) DEFAULT NULL,
  `extra` varchar(100) DEFAULT '',
  PRIMARY KEY (`id`,`progname`),
  KEY `extra` (`extra`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table structure for crash
-- ----------------------------
DROP TABLE IF EXISTS `crash`;
CREATE TABLE `crash` (
  `filepath` varchar(500) CHARACTER SET ascii NOT NULL,
  `fuzzer` varchar(255) DEFAULT NULL,
  `progname` varchar(255) DEFAULT NULL,
  `experiment` varchar(255) DEFAULT NULL,
  `dupN` int(11) DEFAULT NULL,
  `filesize` varchar(255) DEFAULT NULL,
  `createtime` int(11) DEFAULT NULL,
  `timeouted` tinyint(4) DEFAULT NULL,
  `asanvalidated` tinyint(4) DEFAULT NULL,
  `gccasan_vulntype` varchar(255) DEFAULT NULL,
  `gccasan_full` longtext CHARACTER SET ascii DEFAULT NULL,
  `gccasan_fullraw` longtext DEFAULT NULL,
  `gccasan_uniq` longtext DEFAULT NULL,
  `gccasan_1` varchar(255) DEFAULT NULL,
  `gccasan_2` varchar(500) DEFAULT NULL,
  `gccasan_3` varchar(1000) CHARACTER SET ascii DEFAULT NULL,
  `gccasan_4` varchar(1000) DEFAULT NULL,
  `gccasan_5` varchar(1000) DEFAULT NULL,
  `gdbvalidated` tinyint(4) DEFAULT NULL COMMENT '-1=timeout 0=not crash 1=crash 2=crash and timeout',
  `exploitable` varchar(255) DEFAULT '' COMMENT 'short_description',
  `exploitable_class` varchar(255) DEFAULT NULL,
  `exploitable_hash1` varchar(255) DEFAULT NULL,
  `exploitable_hash2` varchar(255) DEFAULT NULL,
  `gdb_stacktrace3` varchar(1000) DEFAULT NULL,
  `bugid` int(11) DEFAULT NULL,
  `cve` varchar(255) DEFAULT NULL,
  `cvss_v2` float DEFAULT NULL,
  `cvss_v3` float DEFAULT NULL,
  `queuetocrash` int(11) DEFAULT -1,
  PRIMARY KEY (`filepath`),
  KEY `exploitable_hash1` (`exploitable_hash1`),
  KEY `progname` (`progname`),
  KEY `exploitable_class` (`exploitable_class`),
  KEY `cve` (`cve`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------
-- Table structure for dockers
-- ----------------------------
DROP TABLE IF EXISTS `dockers`;
CREATE TABLE `dockers` (
  `server` varchar(10) NOT NULL DEFAULT '',
  `name` varchar(255) DEFAULT NULL,
  `id` varchar(255) NOT NULL DEFAULT '',
  `starttime` int(11) DEFAULT NULL,
  `runningtime` int(11) DEFAULT NULL,
  `memlimit` int(11) DEFAULT NULL,
  `foldername` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`,`server`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
