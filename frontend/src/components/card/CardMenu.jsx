import React from "react";
import Dropdown from "components/dropdown";
import { AiOutlineUser } from "react-icons/ai";
import { BsThreeDots } from "react-icons/bs";
import { FiSettings } from "react-icons/fi";
import { AiOutlineShop } from "react-icons/ai";
import { TiLightbulb } from "react-icons/ti";

function CardMenu(props) {
  const { transparent } = props;
  const [open, setOpen] = React.useState(false);
  return (
    <Dropdown
      button={
        <button
          onClick={() => setOpen(!open)}
          open={open}
          className={`flex items-center text-xl hover:cursor-pointer ${
            transparent
              ? "bg-none text-white hover:bg-none active:bg-none"
              : "bg-lightPrimary p-2 text-brand-500 hover:bg-gray-100 dark:bg-navy-700 dark:text-white dark:hover:bg-white/20 dark:active:bg-white/10"
          } linear justify-center rounded-lg font-bold transition duration-200`}
        >
          <BsThreeDots className="h-6 w-6" />
        </button>
      }
      animation={"origin-top-right transition-all duration-300 ease-in-out"}
      classNames={`${transparent ? "top-8" : "top-11"} right-0 w-max`}
    />
  );
}

export default CardMenu;
