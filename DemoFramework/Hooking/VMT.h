#pragma once
namespace DemoFrame
{
	namespace Hooking
	{
		class VMT
		{
		public:
			///Constructor
			VMT();
			///explicit constructor
			explicit VMT(PDWORD*);
			///Destructor
			~VMT();
			///<summary> Adds a Hook
			///<para> This Function find the index of the vtable and sets it to redirect to your own Function, this method is makes it easy to unhook by calling <see cref="VMT::DestryHooks"/></para>
			///</summary>
			DWORD AddHook(DWORD, UINT);

			///<summary> Destroys Hooked Functions
			///<para> This Function Set back the original function, To Add hooks to be destroyed see <see cref="VMT::AddHook"/></para>
			///</summary>
			void DestroyHooks();

			///<summary> Destroys a Single Hook
			///<para> This Function Set back the original function <see cref="VMT::AddHook"/></para>
			///</summary>
			void DestroyHookExclusive(UINT);

			///<summary> Returns Original VTable
			///<para> This Function Will return the VTable in its Original State</para>
			///</summary>
			DWORD* _VMT() const;

			///<summary> Returns Original VTable of a given index
			///<para> This Function Will return the VTable at a specific address in its Original State</para>
			///</summary>
			DWORD _VMTAddress(UINT) const;

			///<summary> Returns the size of the VTable
			///<para> This Function will return the VTable size</para>
			///</summary>
			int _VMTSize() const;
		private:
			///<summary> Works with the destructor </summary>
			void Destroy() const;

			///<summary> Construtors</summary>
			void Init(PDWORD*&);

			///<summary> Construtors</summary>
			void Init(PDWORD**);

			///<summary> Initalizes Variables </summary>
			void SetVars(PDWORD*);

			///<summary> Sets the Pointer Redirection
			///<para> This Function will redirect the Pointer for the vtable to a user defined redirect</para>
			///</summary>
			void SetRedirect() const;

			///<summary>Gets the size of the VTable
			///<para> This Function will return the VTable size</para>
			///</summary>
			static DWORD GetVMTSize(PDWORD);

			PDWORD* _dwClassBase;
			PDWORD __dwVMT, _dwVMT;
			DWORD _dwVMTSize;
			std::vector<UINT> __Index;
		};

	};

}