-- phpMyAdmin SQL Dump
-- version 5.3.0-dev
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Nov 23, 2022 at 10:04 PM
-- Server version: 8.0.31-0ubuntu0.20.04.1
-- PHP Version: 7.4.3

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `mami`
--

-- --------------------------------------------------------

--
-- Table structure for table `oauth`
--

CREATE TABLE `oauth` (
  `misskey_token` text NOT NULL,
  `mstdn_token` text NOT NULL,
  `instance_domain` text NOT NULL,
  `legacy_mode` tinyint(1) NOT NULL DEFAULT '0',
  `app_name` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `oauth_pending`
--

CREATE TABLE `oauth_pending` (
  `session_id` text NOT NULL,
  `client_name` text NOT NULL,
  `scope` text NOT NULL,
  `redirect_uri` text NOT NULL,
  `instance_domain` text,
  `miauth_session_id` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci,
  `legacy_mode` tinyint(1) NOT NULL DEFAULT '0',
  `legacy_token` text,
  `legacy_secret` text,
  `misskey_token` text,
  `authcode` text
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
