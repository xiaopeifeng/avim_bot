// 
// Simple app with avim_bot
//
// Group bot Impl
//

#include <string>
#include <iostream>
#include <fstream>

#include <boost/format.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/make_shared.hpp>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include "bot_api.hpp"
#include "logging.hpp"

fs::path setup_ini;

void program_options_load(int argc, char **argv)
{
	po::options_description desc("Allowed options");
	po::variables_map vm;
	
	desc.add_options()
	("help,h", "produce help message")
	("version,v", "print version string")
	("title", po::value<fs::path>(&setup_ini)->default_value("group.ini"), "path to group bot setup ini file")
	;
	
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);
	
	if(argc == 1 || vm.count("help"))
	{
		LOG_DBG << desc;
		return;
	}
	
	if(vm.count("version"))
	{
		LOG_DBG << "Version:0.1";
		return;
	}
	
	return;
}
int main(int argc, char **argv)
{
	LOG_DBG << "Group bot starting ";
	program_options_load(argc, argv);

	bot_init();
	while(1)
	{
		sleep(1);
	}
	
	return 0;
}
