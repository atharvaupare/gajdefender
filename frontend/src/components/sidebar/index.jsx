/* eslint-disable */

import { HiX } from "react-icons/hi";
import Links from "./components/Links";

// import SidebarCard from "components/sidebar/componentsrtl/SidebarCard";
import routes from "routes.js";

const Sidebar = ({ open, onClose }) => {
  return (
    <div
      className={`sm:none duration-175 linear fixed !z-50 flex min-h-full flex-col bg-white pb-10 shadow-2xl shadow-white/5 transition-all dark:!bg-navy-800 dark:text-white md:!z-50 lg:!z-50 xl:!z-0 ${
        open ? "translate-x-0" : "-translate-x-96"
      }`}
    >
      <span
        className="absolute right-4 top-4 block cursor-pointer xl:hidden"
        onClick={onClose}
      >
        <HiX />
      </span>

      <div className="mx-[76px] mt-[50px] flex items-center gap-4">
        {/* Logo */}
        <img
          src="https://mail.google.com/mail/u/2?ui=2&ik=73c4992d69&attid=0.1&permmsgid=msg-f:1829262965937346157&th=1962d8f9c579166d&view=fimg&fur=ip&permmsgid=msg-f:1829262965937346157&sz=s0-l75-ft&attbid=ANGjdJ9mQDmhZVcDt9TkAvPGqDho-knKqS45sJ7dcwllPOl322isq3fhKZ8UAoGB_hiSXoQ4P8cLjO6MqnVk3ulB3-tiR32S9NYQM9Kn46XtOslDRfUjAvy4l2nhjgw&disp=emb&realattid=ii_m9f6tczh0&zw"
          alt="GajShield Logo"
          className="h-[160px] "
        />

        {/* Title */}
        {/* <div className="ml-1 mt-1 font-poppins text-[26px] font-bold uppercase text-navy-700 dark:text-white">
          HACK 8.0
        </div> */}
      </div>

      <div class="mb-7 mt-[58px] h-px bg-gray-300 dark:bg-white/30" />
      {/* Nav item */}

      <ul className="mb-auto pt-1">
        <Links routes={routes} />
      </ul>

      {/* Nav item end */}
    </div>
  );
};

export default Sidebar;
