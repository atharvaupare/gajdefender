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

      <div className="mx-[56px] mt-[50px] flex items-center gap-4">
        {/* Logo */}
        <img
          src="https://www.gajshield.com/images/2020/04/01/gajshieldlogo4x.png"
          alt="GajShield Logo"
          className="h-10 w-auto"
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
